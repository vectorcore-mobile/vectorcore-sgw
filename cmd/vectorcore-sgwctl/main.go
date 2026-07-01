package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	sgwuconfig "vectorcore-sgw/internal/config/sgwu"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

type commandError struct {
	code int
	err  error
}

func (e commandError) Error() string { return e.err.Error() }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var ce commandError
		if errors.As(err, &ce) {
			fmt.Fprintln(os.Stderr, ce.err)
			os.Exit(ce.code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vectorcore-sgwctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("v", false, "print version and exit")
	sgwcAPI := fs.String("sgwc-api", "http://127.0.0.1:8080", "SGW-C API base URL")
	sgwuAPI := fs.String("sgwu-api", "http://127.0.0.1:8081", "SGW-U API base URL")
	timeout := fs.Duration("timeout", 5*time.Second, "HTTP request timeout")
	fs.Usage = func() { usage(stderr, fs) }
	if err := fs.Parse(args); err != nil {
		return commandError{code: 2, err: err}
	}
	if *showVersion {
		fmt.Fprintf(stdout, "VectorCore sgwctl %s\nbuild_date: %s\ngo: %s\n", version, buildDate, runtime.Version())
		return nil
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return commandError{code: 2, err: fmt.Errorf("missing command")}
	}

	c := &ctl{
		stdout:  stdout,
		stderr:  stderr,
		sgwcAPI: strings.TrimRight(*sgwcAPI, "/"),
		sgwuAPI: strings.TrimRight(*sgwuAPI, "/"),
		client:  &http.Client{Timeout: *timeout},
	}
	switch fs.Arg(0) {
	case "validate":
		return c.validate(fs.Args()[1:])
	case "dry-run":
		return c.validate(fs.Args()[1:])
	case "health":
		return c.fetch("SGW-C health", c.sgwcAPI, "/health")
	case "sessions":
		return c.fetch("SGW-C sessions", c.sgwcAPI, "/sessions")
	case "bearers":
		return c.fetch("SGW-C bearers", c.sgwcAPI, "/sessions")
	case "pfcp":
		return c.fetchBoth("/pfcp/associations")
	case "bpf":
		return c.fetch("SGW-U BPF rules", c.sgwuAPI, "/bpf/rules")
	default:
		fs.Usage()
		return commandError{code: 2, err: fmt.Errorf("unknown command %q", fs.Arg(0))}
	}
}

type ctl struct {
	stdout  io.Writer
	stderr  io.Writer
	sgwcAPI string
	sgwuAPI string
	client  *http.Client
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "Usage: vectorcore-sgwctl [flags] <command> [args]\n\n")
	fmt.Fprintf(w, "Commands:\n")
	fmt.Fprintf(w, "  validate   Validate SGW-C and/or SGW-U config files\n")
	fmt.Fprintf(w, "  dry-run    Alias for validate; no sockets or BPF hooks are opened\n")
	fmt.Fprintf(w, "  health     Show SGW-C health\n")
	fmt.Fprintf(w, "  sessions   List SGW-C sessions\n")
	fmt.Fprintf(w, "  bearers    List SGW-C sessions with bearer details\n")
	fmt.Fprintf(w, "  pfcp       Show SGW-C and SGW-U PFCP association status\n")
	fmt.Fprintf(w, "  bpf        Show SGW-U BPF map state\n")
	fmt.Fprintf(w, "\nValidate examples:\n")
	fmt.Fprintf(w, "  vectorcore-sgwctl validate -sgwc configs/sgw-c.yaml -sgwu configs/sgw-u.yaml\n")
	fmt.Fprintf(w, "  vectorcore-sgwctl dry-run -sgwc configs/interop/sgw-c-lab.yaml\n")
	fmt.Fprintf(w, "\nFlags:\n")
	fs.PrintDefaults()
}

func (c *ctl) validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	sgwcPath := fs.String("sgwc", "", "SGW-C config path")
	sgwuPath := fs.String("sgwu", "", "SGW-U config path")
	if err := fs.Parse(args); err != nil {
		return commandError{code: 2, err: err}
	}
	if *sgwcPath == "" && *sgwuPath == "" {
		return commandError{code: 2, err: fmt.Errorf("validate requires -sgwc and/or -sgwu")}
	}
	if *sgwcPath != "" {
		cfg, err := sgwcconfig.Load(*sgwcPath)
		if err != nil {
			return fmt.Errorf("SGW-C config invalid: %w", err)
		}
		fmt.Fprintf(c.stdout, "SGW-C config valid: %s\n", *sgwcPath)
		fmt.Fprintf(c.stdout, "  node_id=%s s11=%s s5c=%s pfcp=%s sgwu_peers=%d\n",
			cfg.SGWC.NodeID, cfg.S11Listen(), cfg.S5CListen(), cfg.PFCP.LocalAddr, len(cfg.PFCP.SGWU))
	}
	if *sgwuPath != "" {
		cfg, err := sgwuconfig.Load(*sgwuPath)
		if err != nil {
			return fmt.Errorf("SGW-U config invalid: %w", err)
		}
		fmt.Fprintf(c.stdout, "SGW-U config valid: %s\n", *sgwuPath)
		fmt.Fprintf(c.stdout, "  node_id=%s pfcp=%s s1u=%s s5u=%s dataplane=ebpf driver_mode=%s\n",
			cfg.SGWU.NodeID, cfg.PFCP.Listen, cfg.GTPU.S1U.Bind, cfg.GTPU.S5U.Bind, cfg.Dataplane.DriverMode)
	}
	return nil
}

func (c *ctl) fetch(title, base, path string) error {
	body, err := c.get(base, path)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%s\n", title)
	return prettyPrint(c.stdout, body)
}

func (c *ctl) fetchBoth(path string) error {
	if err := c.fetch("SGW-C PFCP associations", c.sgwcAPI, path); err != nil {
		return err
	}
	fmt.Fprintln(c.stdout)
	return c.fetch("SGW-U PFCP associations", c.sgwuAPI, path)
}

func (c *ctl) get(base, path string) ([]byte, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL %q: %w", base, err)
	}
	ref, _ := url.Parse(path)
	full := u.ResolveReference(ref).String()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", full, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", full, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("GET %s: status %s: %s", full, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func prettyPrint(w io.Writer, body []byte) error {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		_, writeErr := w.Write(body)
		return writeErr
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

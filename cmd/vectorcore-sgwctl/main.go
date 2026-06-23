package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	showVersion := flag.Bool("v", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: vectorcore-sgwctl [flags] <command> [args]\n\n")
		fmt.Fprintf(os.Stderr, "Commands:\n")
		fmt.Fprintf(os.Stderr, "  sessions   List active sessions\n")
		fmt.Fprintf(os.Stderr, "  bearers    List active bearers\n")
		fmt.Fprintf(os.Stderr, "  pfcp       Show PFCP association status\n")
		fmt.Fprintf(os.Stderr, "  bpf        Show BPF map state\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("VectorCore sgwctl %s\nbuild_date: %s\ngo: %s\n", version, buildDate, runtime.Version())
		return
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "vectorcore-sgwctl: command %q not yet implemented\n", flag.Arg(0))
	os.Exit(1)
}

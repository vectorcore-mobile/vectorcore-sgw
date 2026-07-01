package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateConfigs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"validate",
		"-sgwc", "../../configs/interop/sgw-c-lab.yaml",
		"-sgwu", "../../configs/interop/sgw-u-lab.yaml",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run validate: %v stderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "SGW-C config valid") || !strings.Contains(out, "SGW-U config valid") {
		t.Fatalf("validate output = %q", out)
	}
	if !strings.Contains(out, "dataplane=ebpf") {
		t.Fatalf("validate output missing dataplane summary: %q", out)
	}
}

func TestValidateRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"validate"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("validate without config succeeded")
	}
	var ce commandError
	if !asCommandError(err, &ce) || ce.code != 2 {
		t.Fatalf("error = %#v; want commandError code 2", err)
	}
}

func TestFetchSessionsPrettyPrintsJSON(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions" {
			t.Fatalf("path = %s; want /sessions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessions":[{"session_id":"abc"}],"total":1}`))
	}))
	defer api.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"-sgwc-api", api.URL, "sessions"}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run sessions: %v stderr=%s", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "SGW-C sessions") || !strings.Contains(out, `"session_id": "abc"`) {
		t.Fatalf("sessions output = %q", out)
	}
}

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-v"}, &stdout, &stderr); err != nil {
		t.Fatalf("run -v: %v", err)
	}
	if !strings.Contains(stdout.String(), "VectorCore sgwctl") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func asCommandError(err error, target *commandError) bool {
	if ce, ok := err.(commandError); ok {
		*target = ce
		return true
	}
	return false
}

package api

import (
	"log/slog"
	"strings"
	"testing"
)

func TestNewServerUsesComponentInOpenAPITitleAndHealth(t *testing.T) {
	srv := NewServer("127.0.0.1:0", BuildInfo{Component: "SGW-U", Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))

	var spec struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	getJSON(t, srv, "/openapi.json", &spec)
	if spec.Info.Title != "VectorCore SGW-U API" {
		t.Fatalf("OpenAPI title = %q; want VectorCore SGW-U API", spec.Info.Title)
	}

	var health HealthOutput
	getJSON(t, srv, "/health", &health.Body)
	if health.Body.Component != "SGW-U" {
		t.Fatalf("health component = %q; want SGW-U", health.Body.Component)
	}
}

func TestNewServerDefaultComponentStillIdentifiesSGW(t *testing.T) {
	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))

	var spec struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	getJSON(t, srv, "/openapi.json", &spec)
	if !strings.Contains(spec.Info.Title, "SGW") {
		t.Fatalf("OpenAPI title = %q; want SGW identity", spec.Info.Title)
	}
}

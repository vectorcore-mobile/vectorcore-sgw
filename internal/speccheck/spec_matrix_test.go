package speccheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

type matrixFile struct {
	Spec      string      `json:"spec"`
	Procedure string      `json:"procedure"`
	Rule      string      `json:"rule"`
	Rows      []matrixRow `json:"rows"`
}

type matrixRow struct {
	ID       string   `json:"id"`
	IEType   int      `json:"ie_type"`
	IEName   string   `json:"ie_name"`
	Action   string   `json:"action"`
	Tests    []string `json:"tests"`
	Source   string   `json:"source"`
	Target   string   `json:"target"`
	Presence string   `json:"presence"`
}

func TestTS29274SpecMatricesHaveExecutableCoverage(t *testing.T) {
	matrixPaths, err := filepath.Glob(filepath.Join("..", "..", "docs", "spec-matrix", "ts29274-*.json"))
	if err != nil {
		t.Fatalf("glob matrices: %v", err)
	}
	if len(matrixPaths) == 0 {
		t.Fatal("no TS 29.274 spec matrices found")
	}
	testFuncs := collectTestFunctions(t)

	for _, matrixPath := range matrixPaths {
		t.Run(filepath.Base(matrixPath), func(t *testing.T) {
			raw, err := os.ReadFile(matrixPath)
			if err != nil {
				t.Fatalf("read matrix: %v", err)
			}
			var matrix matrixFile
			if err := json.Unmarshal(raw, &matrix); err != nil {
				t.Fatalf("parse matrix: %v", err)
			}
			if matrix.Spec != "3GPP TS 29.274 Rel-15" {
				t.Fatalf("matrix spec = %q; want 3GPP TS 29.274 Rel-15", matrix.Spec)
			}
			seenIDs := map[string]bool{}
			for _, row := range matrix.Rows {
				if row.ID == "" {
					t.Fatalf("matrix row with empty id: %+v", row)
				}
				if seenIDs[row.ID] {
					t.Fatalf("duplicate matrix id %q", row.ID)
				}
				seenIDs[row.ID] = true
				if row.Source == "" || row.Target == "" || row.IEName == "" || row.Presence == "" {
					t.Fatalf("matrix row %s missing required source/target/name/presence metadata: %+v", row.ID, row)
				}
				if row.Action != "preserve" && row.Action != "generate" && row.Action != "validate" && row.Action != "omit" {
					t.Fatalf("matrix row %s has unsupported action %q", row.ID, row.Action)
				}
				if row.Action == "preserve" || row.Action == "generate" || row.Action == "validate" {
					if len(row.Tests) == 0 {
						t.Fatalf("matrix row %s action=%s has no tests", row.ID, row.Action)
					}
					for _, name := range row.Tests {
						if !testFuncs[name] {
							t.Fatalf("matrix row %s references missing Go test %s", row.ID, name)
						}
					}
				}
			}
		})
	}
}

func collectTestFunctions(t *testing.T) map[string]bool {
	t.Helper()
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "docs", "pcap":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || len(path) < len("_test.go") || path[len(path)-len("_test.go"):] != "_test.go" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllSubmatch(raw, -1) {
			out[string(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("collect test functions: %v", err)
	}
	return out
}

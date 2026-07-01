// Package bpf holds the XDP GTP-U dataplane program for SGW-U.
// Run `go generate` from this directory to compile the BPF object and
// regenerate the Go bindings (requires clang and libbpf-dev).
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -output-dir . TcSgwGtpu ../../../ebpf/tc_sgw_gtpu.c -- -I../../../ebpf/headers -I/usr/include -I/usr/include/x86_64-linux-gnu -O2 -Wall

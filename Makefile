SGWC_APP    = sgw-c
SGWU_APP    = sgw-u
SGWCTL_APP  = sgwctl
BIN_DIR     = bin
BPF_OBJ     = internal/dataplane/bpf/xdpsgwgtpu_bpfel.o
PREFIX     ?= /opt/vectorcore
SYSCONFDIR ?= /etc
SYSTEMD_DIR ?= $(SYSCONFDIR)/systemd/system

GOCACHE    ?= /tmp/vectorcore-sgw-gocache
GOMODCACHE ?= /tmp/vectorcore-sgw-gomodcache
GOENV       = GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)

VERSION    ?= 0.2.2
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     = -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build generate tidy test vet spec-check verify clean install install-check uninstall

build: generate
	install -d $(BIN_DIR)
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWC_APP)   ./cmd/vectorcore-sgw-c
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWU_APP)   ./cmd/vectorcore-sgw-u
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWCTL_APP) ./cmd/vectorcore-sgwctl

generate:
	$(GOENV) go generate ./internal/dataplane/...

tidy:
	$(GOENV) go mod tidy

test: generate
	$(GOENV) go test ./...

vet:
	$(GOENV) go vet ./...

spec-check:
	$(GOENV) go test ./internal/speccheck -count=1

verify: generate vet spec-check test
	$(GOENV) go build -buildvcs=false ./...

clean:
	rm -rf $(BIN_DIR) $(BPF_OBJ)

install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -d $(DESTDIR)$(PREFIX)/etc
	install -d $(DESTDIR)$(PREFIX)/log
	install -d $(DESTDIR)$(PREFIX)/docs
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -m 0755 $(BIN_DIR)/$(SGWC_APP)   $(DESTDIR)$(PREFIX)/bin/$(SGWC_APP)
	install -m 0755 $(BIN_DIR)/$(SGWU_APP)   $(DESTDIR)$(PREFIX)/bin/$(SGWU_APP)
	install -m 0755 $(BIN_DIR)/$(SGWCTL_APP) $(DESTDIR)$(PREFIX)/bin/$(SGWCTL_APP)
	install -m 0644 configs/sgw-c.yaml $(DESTDIR)$(PREFIX)/etc/sgw-c.yaml
	install -m 0644 configs/sgw-u.yaml $(DESTDIR)$(PREFIX)/etc/sgw-u.yaml
	install -m 0644 docs/production-controls.md $(DESTDIR)$(PREFIX)/docs/production-controls.md
	install -m 0644 deploy/systemd/vectorcore-sgw-c.service $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-c.service
	install -m 0644 deploy/systemd/vectorcore-sgw-u.service $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-u.service

install-check:
	test -x $(DESTDIR)$(PREFIX)/bin/$(SGWC_APP)
	test -x $(DESTDIR)$(PREFIX)/bin/$(SGWU_APP)
	test -x $(DESTDIR)$(PREFIX)/bin/$(SGWCTL_APP)
	test -f $(DESTDIR)$(PREFIX)/etc/sgw-c.yaml
	test -f $(DESTDIR)$(PREFIX)/etc/sgw-u.yaml
	test -f $(DESTDIR)$(PREFIX)/docs/production-controls.md
	test -f $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-c.service
	test -f $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-u.service

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/$(SGWC_APP)
	rm -f $(DESTDIR)$(PREFIX)/bin/$(SGWU_APP)
	rm -f $(DESTDIR)$(PREFIX)/bin/$(SGWCTL_APP)
	rm -f $(DESTDIR)$(PREFIX)/etc/sgw-c.yaml
	rm -f $(DESTDIR)$(PREFIX)/etc/sgw-u.yaml
	rm -f $(DESTDIR)$(PREFIX)/docs/production-controls.md
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-c.service
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/vectorcore-sgw-u.service

SGWC_APP    = vectorcore-sgw-c
SGWU_APP    = vectorcore-sgw-u
SGWCTL_APP  = vectorcore-sgwctl
BIN_DIR     = bin

GOCACHE    ?= /tmp/vectorcore-sgw-gocache
GOMODCACHE ?= /tmp/vectorcore-sgw-gomodcache
GOENV       = GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)

VERSION    ?= 0.1.0
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     = -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build generate tidy test clean install

build: generate
	install -d $(BIN_DIR)
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWC_APP)   ./cmd/vectorcore-sgw-c
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWU_APP)   ./cmd/vectorcore-sgw-u
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(SGWCTL_APP) ./cmd/vectorcore-sgwctl

generate:
	$(GOENV) go generate ./internal/dataplane/...

tidy:
	$(GOENV) go mod tidy

test:
	$(GOENV) go test ./...

clean:
	rm -rf $(BIN_DIR)

install: build
	install -d /opt/vectorcore/sgw/bin
	install -d /etc/vectorcore/sgw
	install -d /var/log/vectorcore/sgw
	install -m 0755 $(BIN_DIR)/$(SGWC_APP)   /opt/vectorcore/sgw/bin/$(SGWC_APP)
	install -m 0755 $(BIN_DIR)/$(SGWU_APP)   /opt/vectorcore/sgw/bin/$(SGWU_APP)
	install -m 0755 $(BIN_DIR)/$(SGWCTL_APP) /opt/vectorcore/sgw/bin/$(SGWCTL_APP)

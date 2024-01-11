EXAMPLE_PROJECT = rscni-debug

EXAMPLE_BIN_DIR = ../target/release/examples/

.PHONY: build
build:
	cargo build --release --example $(EXAMPLE_PROJECT)

.PHONY: clean
clean:
	cargo clean


.PHONY: start
start: build
	kind create cluster
	docker cp $(EXAMPLE_BIN_DIR)/$(EXAMPLE_PROJECT) kind-control-plane:/opt/cni/bin/$(EXAMPLE_PROJECT)
	docker cp ./netconf.json kind-control-plane:/etc/cni/net.d/01-rscni-debug.conflist

.PHONY: stop
stop: clean
	kind delete cluster


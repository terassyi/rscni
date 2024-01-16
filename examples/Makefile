EXAMPLE_PROJECT = rscni-debug
ASYNC ?= false
EXAMPLE_BIN_DIR = ../target/release

.PHONY: build
build:
	cd $(EXAMPLE_PROJECT); cargo build --release
	cd async-$(EXAMPLE_PROJECT); cargo build --release

.PHONY: clean
clean:
	cargo clean



.PHONY: start
start: build
	kind create cluster
ifeq ($(ASYNC),true)
	docker cp $(EXAMPLE_BIN_DIR)/async-$(EXAMPLE_PROJECT) kind-control-plane:/opt/cni/bin/$(EXAMPLE_PROJECT)
else
	docker cp $(EXAMPLE_BIN_DIR)/$(EXAMPLE_PROJECT) kind-control-plane:/opt/cni/bin/$(EXAMPLE_PROJECT)
endif
	docker cp ./netconf.json kind-control-plane:/etc/cni/net.d/01-rscni-debug.conflist

.PHONY: stop
stop: clean
	kind delete cluster


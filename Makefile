PROJECT_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: build dependencies wasm go-test rust-test go-dependencies rust-dependencies

rust-dependencies:
	cd lib && cargo build

go-dependencies:
	cd $(PROJECT_DIR) && go get -d -v ./...

dependencies: rust-dependencies go-dependencies

go-test: wasm go-dependencies
	cd $(PROJECT_DIR) && go test ./...

rust-test: rust-dependencies
	cd $(PROJECT_DIR)/lib && cargo test

wasm:
	cd lib && cargo build --target wasm32-unknown-unknown --release
	mkdir -p $(PROJECT_DIR)/pkg/cedar/static
	cp lib/target/wasm32-unknown-unknown/release/cedar-wasm.wasm $(PROJECT_DIR)/static/cedar.wasm

build: dependencies wasm


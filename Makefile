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
	cd $(PROJECT_DIR)/lib && cargo build --target wasm32-unknown-unknown --release
	mkdir -p $(PROJECT_DIR)/static
	cp $(PROJECT_DIR)/lib/target/wasm32-unknown-unknown/release/cedarwasm.wasm $(PROJECT_DIR)/static/cedar.wasm

build: dependencies wasm


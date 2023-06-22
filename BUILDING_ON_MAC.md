# Building on macos

The version of llvm that ships with MacOS is not suitable for compiling to wasm
See below from ChatGPT

```
Installing LLVM from Homebrew on macOS provides the necessary components for building and working with WebAssembly (Wasm) binaries using Rust. LLVM (Low-Level Virtual Machine) is a compiler infrastructure that includes tools and libraries for code generation, optimization, and more.
When you install LLVM from Homebrew, it typically installs the llvm formula, which includes the LLVM compiler, libraries, and utilities. In the context of building WebAssembly with Rust, installing LLVM via Homebrew helps set up the appropriate toolchain and provides the required dependencies for generating Wasm binaries.
Rust leverages LLVM for its powerful optimization capabilities and code generation. The Rust compiler (rustc) uses LLVM in the background to produce machine code for various targets, including the WebAssembly target (wasm32-unknown-unknown).
By installing LLVM through Homebrew, you ensure that the necessary LLVM components and dependencies are available on your macOS system, allowing the Rust compiler to properly target and build WebAssembly binaries.
Note that the specific details of LLVM installation and usage may vary based on your system configuration and the version of LLVM available through Homebrew. It's always a good idea to consult the documentation and resources specific to your development environment for accurate installation instructions and troubleshooting guidance.
```

So to building the wasm binary follow these steps:

```
brew install llvm
```

then

```
LLVM_PATH=$(brew --prefix llvm)
export AR="${LLVM_PATH}/bin/llvm-ar"
export CC="${LLVM_PATH}/bin/clang"
make build
```
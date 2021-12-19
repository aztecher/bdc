# BDC - eBPF DNS Cache

**This project is currently under development**

BDC is the eBPF powered DNS caching mechanism in kernel inspired by [BMC](https://www.usenix.org/conference/nsdi21/presentation/ghigoff)

## Setup

This program depends on 'aya' project, so you have to setup prerequists for using 'aya'

### setup nightly rust and related packages

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install --git https://github.com/aya-rs/bpf-linker  --tag v0.9.2 --no-default-features --features rust-llvm -- bpf-linker
cargo +nightly install cargo-generate
```

## Build

First, build eBPF program and generate bytecode

```bash
cargo xtask build-ebpf
```

The bytecode will be located on `target/bpfel-unknown-none/debug/bdc` and loaded in user program

Second, build userspace program

```bash
cargo build
```

The binary file 'bdc' are created and located on `target/debug/bdc`

## Usage

```bash
$ ./target/debug/bdc -h
bdc 0.1.0

USAGE:
    bdc [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bpftype <bpftype>     [default: xdp]
    -i, --iface <iface>         [default: eth0]
```

## Benchmarks

TODO

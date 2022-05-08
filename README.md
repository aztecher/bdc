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

Create list `./bdc/config/block.list` of blocking ip and `./bdc/config/cache.list` of cache FQDN/IP (Originally, it would match cached DNS requests once they come in, but since it's not implemented yet, we'll warm up the cache from the configuration file for now)

`block.list` contains the source ip address that is allowed in DNS configuration.  
`cache.list` contains the FQDN and ip address pair list.  

for example, if you want to analyze DNS query that requests the A record (`192.168.1.2`) of FQDN (`test.example.com`) from a client (`192.168.0.2`) that is allowed in DNS configuration, then you create `block.list` and `cache.list` as follows

```bash
$ cat block.list
192.168.0.2

$ cat cache.lsit
test.example.com 192.168.1.2
```

as mentioned above, `cache.list` is used to warm up the DNS cache.  
`block.list` is used due to specify the target request by any host. So in this example, a DNS query that is only from `192.168.0.2` will be analyzed.
**bdc is under development** and now it try to parse question section and if success, then print out the result.

```bash
# DNS server side execute bdc and wait for request
$ sudo -E ENV_BLOCK_LIST=./block.list ENV_DNS_CACHE=./cache.list ./target/debug/bdc -i <iface>

# Create DNS request to above DNS server from other server that is one of the block.list entry.
$ dig @<DNS Server IP Address> test.example.com

# Then, bdc outputs the cache hit output.
Cache hit ip address = 192.168.1.2
```

`ENV_BLOCK_LIST`, `ENV_DNS_CACHE` environmental variable are used to detect the filepath of `block.list` and `cache.list`.
If you want to try `bdc` but don't have your own DNS server, the [documents](./docs/bind/setup.md) will help you to setup minimal testbed.

## Benchmarks

TODO

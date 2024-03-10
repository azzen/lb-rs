# load-balancer

This is a demo program to play with eBPF + XDP in Rust using aya-rs.

The code is from: https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust and has been slightly adapted to changes made to the APIs since 2022.

The program has been tested on a virtual machine with the following configuration:

- Ubuntu 22.04 x86_64
- Kernel version: 6.5.0-25

A sample testing program is also provided, see `load-balancer-server`.

The load-balancer implements a round robin strategy and is stateless, do not use it in production.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

Test program:

```bash
cargo run --bin server
```
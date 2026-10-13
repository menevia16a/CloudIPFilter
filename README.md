# CloudIPFilter

An advanced C++ CLI tool designed for cybersecurity professionals (Bug Bounty hunters) to filter out cloud infrastructure noise (Cloudflare, AWS, Akamai, etc.) from IP lists.

## Features

- **Two-Layer Detection Engine**:
  - **Passive Layer**: High-speed CIDR matching against known cloud provider ranges.
  - **Active Probing Layer**: Performs lightweight HTTP HEAD requests to inspect `Server` and `Via` headers for hidden cloud signatures.
- **Order-Independent Arguments**: Use `-i` for input, `-o` for output, and `--help` for assistance in any order.
- **Professional Integration**: Easy installation via `make install`.

## Prerequisites

- `cmake` (3.10+)
- `libcurl` (Development headers)
- `g++` or `clang`

On Debian/Parrot OS:
```bash
sudo apt update
sudo apt install cmake libcurl4-openssl-dev build-essential
```

## Installation

```bash
cd CloudIPFilter
mkdir build && cd build
cmake ..
make
sudo make install
```

## Usage

```bash
# Basic usage (outputs to stdout)
CloudIP    -i targets.txt

# Save results to a file
CloudIPFilter -i targets.txt -o clean_ips.txt

# Using different argument order
CloudIPFilter -o results.txt -i input_list.txt --help
```

## License
MIT
```

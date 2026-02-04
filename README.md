# IOAM Agent

The IOAM (In-situ Operations, Administration, and Maintenance) agent inspects IPv6 traffic, extracts IOAM trace data, and reports them to an IOAM collector or outputs them locally, to the console or to a file. It currently supports packets with IOAM Hop-by-Hop Option header containing IOAM (Pre-allocated) Trace Option-Type.

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.21 or higher)

- (Optional) **PF_RING**: This application may use PF_RING to capture packets more efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

---

## Building the IOAM Agent

```bash
git clone https://github.com/Advanced-Observability/ioam-agent
cd ioam-agent
build
```

### Other targets



---

## Running the IOAM Agent

1. If using the `ioam-agent-pfring`, ensure that the PF_RING kernel module is loaded.

1. **(Optionally) Set the Environment Variable**:
    - `IOAM_COLLECTOR`: Specify the IOAM collector address.

2. **Run the Agent**:
    This will capture IOAM traces of packets received on the specified interface:

    ```bash
    ./ioam-agent -i <interface name>
    ```

    List of arguments:
    - `-i`: Specify the interface name for packet capture (**mandatory**).
    - `-c`: Reporting Option: Specify collector socket (`<ip:port>`) for streaming received IOAM traces with gRPC. `IOAM_COLLECTOR` environment variable can also be used (fallback).
    - `-d`: Reporting Option: Specify file for dumping received IOAM traces to a CSV file.
    - `-s`: Reporting Option: Specify file for exporting agent statistics, updated every second.
    - `-o`: Print IOAM traces to the console.
    - `-g`: Specify the number of goroutines for parsing the packets (default is 8). This might increase the maximum throughput depending on the system.
    - `-h`: Display help.
    **At least one reporting option must be specified**.

    Examples:
    ```bash
    sudo ./ioam-agent-pfring -i eth0 -o
    ```

    ```bash
    sudo ./ioam-agent -d ./ioam-traces.csv -s ./agent-stats.log -i eth0 -c localhost:7123
    ```

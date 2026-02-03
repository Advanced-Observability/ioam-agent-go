# IOAM Agent

The IOAM (In-situ Operations, Administration, and Maintenance) Agent captures IPv6 packets containing IOAM Hop-by-Hop headers, extracts IOAM traces, and reports them to an IOAM collector (or prints them to the console).

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.21 or higher)

- [Protocol Buffers (`protoc`)](https://grpc.io/docs/protoc-installation/): Ensure `protoc` is installed with Go support to compile the `.proto` file. You can download it from.

- (Optional) **PF_RING**: This application may use PF_RING to capture packets more efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

---

## Building the IOAM Agent

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Advanced-Observability/ioam-agent-go
    cd ioam-agent-go
    ```

2. **Generate Protobuf Files**:
    ```bash
    wget https://raw.githubusercontent.com/Advanced-Observability/ioam-api/main/ioam_api.proto
    go generate
    ```

3. **Run the Build Script**:
    The script fetches the `ioam_api.proto` file, compiles it using `protoc`, and then builds the application.

    ```bash
    ./build.sh
    ```

    The script produces the binary `ioam-agent` and if the PF_RING user-land library is available, the binary `ioam-agent-pfring`.
    The two applications are identical expect for the way it retrieves live packets, the PF_RING version will have a much greater throughput.

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

# Ioam Agent

The Ioam (In-situ Operations, Administration, and Maintenance) Agent captures IPv6 packets containing Ioam Hop-by-Hop headers, extracts Ioam traces, and reports them to an Ioam collector (or prints them to the console).

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.21 or higher)

- [Protocol Buffers (`protoc`)](https://grpc.io/docs/protoc-installation/): Ensure `protoc` is installed with Go support to compile the `.proto` file. You can download it from.

- (Optional) **PF_RING**: This application may use PF_RING to capture packets more efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

---

## Building the Ioam Agent

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Advanced-Observability/ioam-agent-go
    cd ioam-agent-go
    ```

2. **Run the Build Script**:
    The script fetches the `ioam_api.proto` file, compiles it using `protoc`, and then builds the application.

    ```bash
    ./build.sh
    ```

    The script produces the binary `ioam-agent` and, if the PF_RING user-land library is available, the binary `ioam-agent-pfring`.
    The two applications are identical expect for the way it retrieves live packets, the PF_RING version will have a much greater throughput.

---

## Running the Ioam Agent

1. If using the `ioam-agent-pfring`, ensure that the PF_RING kernel module is loaded.

1. **(Optionally) Set the Environment Variable**:
    - `IOAM_COLLECTOR`: Specify the Ioam collector address.
    - Ensure PF_RING is loaded and functional.

2. **Run the Agent**:
    - This will capture Ioam traces of packets received on the specified interface:

    ```bash
    ./ioam-agent -i <interface name>
    ```

    - Additional flags:
        - `-g`: Specify the number of goroutines for parsing the packets (default is 8). This might increase the maximum throughput depending on the system.
        - `-o`: Output Ioam traces to the console instead of sending them to an Ioam collector.
        - `-h`: Display help.

    Examples:
    ```bash
    sudo ./ioam-agent-pfring -i eth0 -o
    ```

    ```bash
    sudo IOAM_COLLECTOR=localhost:7123 ./ioam-agent -i eth0

    ```

3. **Logs and Statistics**:
    The agent writes packet statistics (IPv6 and Ioam packets counts) to `./agentStats`. The file is updated every second.

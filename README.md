# IOAM Agent

The IOAM (In-situ Operations, Administration, and Maintenance) Agent is responsible for capturing IPv6 packets with IOAM Hop-by-Hop headers, extracting IOAM traces, and reporting them to a gRPC server or printing them to the console.

## Prerequisites

1. **Go Programming Language**: Make sure Go is installed on your system. You can download it from [here](https://golang.org/doc/install).

2. **PF_RING**: This application uses PF_RING to capture packets efficiently. You can install it from [packages](https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html) or from [Git sources](https://www.ntop.org/guides/pf_ring/get_started/git_installation.html).

3. **Protocol Buffers (`protoc`)**: Ensure `protoc` is installed to compile the `.proto` file. You can download it from [here](https://grpc.io/docs/protoc-installation/).

---

## Building the IOAM Agent

1. **Clone the Repository**:
    ```bash
    git clone https://github.com/Advanced-Observability/ioam-agent-go
    cd ioam-agent-go
    ```

2. **Run the Build Script**:
    The build script fetches the `ioam_api.proto` file, compiles it using `protoc`, and then builds the Go application.

    ```bash
    ./build.sh
    ```

---

## Running the IOAM Agent

1. **Set the Required Environment Variables**:
    - `IOAM_COLLECTOR`: Specify the gRPC collector address (e.g., `localhost:7123`).
    - Ensure PF_RING is loaded and functional.

2. **Run the Agent**:
    - Capture packets on a specified interface:
    
    ```bash
    ./ioam-agent -i <interface-name>
    ```

    - Additional flags:
        - `-g`: Specify the maximum number of goroutines for parsing the packets (default is 8).
        - `-loopback`: Enable packet loopback (send back packet copy).
        - `-o`: Output IOAM traces to the console instead of sending them to a gRPC collector.
        - `-h`: Display help.

    Example:
    ```bash
    sudo ./ioam-agent -i eth0 -o
    ```

3. **Logs and Statistics**:
    The agent writes packet statistics (e.g., number of IPv6 and IOAM packets parsed) to a file (`./agentStats`). You can view these stats in real-time.

---

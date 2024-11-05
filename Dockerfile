FROM golang:1.21-bookworm

# Install required packages
RUN apt-get update && \
  apt-get -y -q install wget lsb-release gnupg && \
  wget -q http://apt.ntop.org/24.04/all/apt-ntop.deb && \
  dpkg -i apt-ntop.deb && \
  apt-get clean all

RUN apt-get update && \
  apt-get -y install pfring

RUN apt-get update && \
  apt-get -y install iproute2

RUN apt-get update && \
    apt-get -y install protoc-gen-go protoc-gen-go-grpc

WORKDIR /apps

# Generate grpc cpp code, and compile ioam agent
COPY ioam_api.proto .
RUN protoc --go_out=. --go-grpc_out=. ioam_api.proto
COPY ioam-agent.go .
RUN go mod init ioam-agent-go
RUN go mod tidy
RUN go build

ENTRYPOINT ["./ioam-agent-go"]
CMD ["-i", "eth0", "-o"]

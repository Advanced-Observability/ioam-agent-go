FROM golang:1.25.6-bookworm

RUN apt-get update && \
    apt-get -y install libpcap-dev

RUN apt-get update && \
    apt-get -y install iproute2

WORKDIR /apps

COPY ../*.go .
COPY ../internal .
RUN go mod init ioam-agent
RUN go mod tidy
RUN go build -o ioam-agent

ENTRYPOINT ["./ioam-agent"]
CMD ["-h"]

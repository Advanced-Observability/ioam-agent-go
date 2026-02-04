FROM ntop/pfring

RUN apt-get update && \
    apt-get -y install golang

RUN apt-get update && \
    apt-get -y install iproute2

WORKDIR /apps

COPY ../*.go .
COPY ../internal .
RUN go mod init ioam-agent
RUN go mod tidy
RUN go build -tags pfring -o ioam-agent-pfring

ENTRYPOINT ["./ioam-agent-pfring"]
CMD ["-h"]

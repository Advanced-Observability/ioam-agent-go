#!/bin/sh

if [ ! -f ioam_api.proto ]; then
  wget https://raw.githubusercontent.com/Advanced-Observability/ioam-api/main/ioam_api.proto
  protoc --go_out=. --go-grpc_out=. ioam_api.proto
fi


go build -o ioam-agent
CGO_LDFLAGS="-L/usr/local/lib -Wl,-rpath=/usr/local/lib" go build -tags pfring -o ioam-agent-pfring

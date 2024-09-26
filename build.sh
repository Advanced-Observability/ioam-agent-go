#!/bin/sh

[ -f ioam_api.proto ] || wget https://raw.githubusercontent.com/Advanced-Observability/ioam-api/main/ioam_api.proto 

protoc --go_out=. --go-grpc_out=. ioam_api.proto
CGO_LDFLAGS="-L/usr/local/lib -Wl,-rpath=/usr/local/lib" go build

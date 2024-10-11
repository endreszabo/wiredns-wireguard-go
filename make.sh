#!/bin/bash

set -o errexit
set -o nounset

PATH=/home/e/go/bin:$PATH
pushd proto

protoc --go_out=. --go-grpc_out=. --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative api.proto

popd

CGO_ENABLED=0 go build -v -ldflags="-s -w"

docker buildx build . --network host -t y7hu/wiredns_wireguard:0.1


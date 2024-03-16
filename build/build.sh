#!/usr/bin/env bash

# Navigate to the root directory of the project
cd "$(dirname "$0")/.."

# Build the application
export GO111MODULE=auto
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/commenter-linux-amd64 ./cmd/commenter

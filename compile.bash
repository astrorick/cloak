#!/bin/bash

# build for Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o build/cloak-linux-amd64 cmd/cloak/main.go

# build for Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o build/cloak-windows-amd64.exe cmd/cloak/main.go

# build for Mac (amd64)
GOOS=darwin GOARCH=amd64 go build -o build/cloak-darwin-amd64 cmd/cloak/main.go

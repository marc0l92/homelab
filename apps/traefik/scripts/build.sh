#!/bin/bash
export GOOS=linux
export GOARCH=amd64

go build -o tophost-dsn-challenge tophost-dsn-challenge.go

#!/bin/bash
GOOS=linux
GOARCH=amd64

go build -o tophost-dsn-challenge tophost-dsn-challenge.go

#!/bin/sh
# apk add go-cross

CGO_ENABLED=0 go build -ldflags "-extldflags -static -s -w" -o httpexec-linux-x64 httpexec.go
GOOS=linux GOARCH=386 CGO_ENABLED=0 go build -ldflags "-extldflags -static -s -w" -o httpexec-linux-i386 httpexec.go
GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o httpexec-win32.exe httpexec.go
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o httpexec-win64.exe httpexec.go
GOOS=freebsd GOARCH=386 go build -ldflags="-s -w" -o httpexec-freebsd-i386.exe httpexec.go
GOOS=freebsd GOARCH=amd64 go build -ldflags="-s -w" -o httpexec-freebsd-x64 httpexec.go
GOOS=openbsd GOARCH=386 go build -ldflags="-s -w" -o httpexec-openbsd-i386 httpexec.go
GOOS=openbsd GOARCH=amd64 go build -ldflags="-s -w" -o httpexec-openbsd-x64 httpexec.go
GOOS=darwin GOARCH=386 go build -ldflags="-s -w" -o httpexec-darwin-i386 httpexec.go
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o httpexec-darwin-x64 httpexec.go


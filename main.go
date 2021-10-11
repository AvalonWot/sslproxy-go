package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	socks "golang.org/x/net/proxy"
)

var _listenAddress = flag.String("listen", ":443", "listen adress:port")
var _tunnelUrl = flag.String("tunnel", "", "tunnel proxy url")
var _proxiesFile = flag.String("proxies_file", "proxies.json", "proxies json file path")
var _useLocalDns = flag.Bool("use_local_dns", false, "switch of use local dns")

var _lock = sync.Mutex{}
var _index = 0
var _latest = time.Now()
var _tunnelDialer socks.Dialer
var _proxiesDialer []socks.Dialer
var _proxiesUrl []string
var _resolver *net.Resolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Millisecond * time.Duration(10000),
		}
		return d.DialContext(ctx, network, "114.114.114.114:53")
	},
}

type ProxiesConfig struct {
	Proxies []string `json:"proxies"`
}

type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func readSNIHost(reader io.Reader) (string, error) {
	var host string
	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host = hello.ServerName
			return nil, nil
		},
	}).Handshake()

	if len(host) == 0 {
		return "", err
	}

	return host, nil
}

const SO_ORIGINAL_DST = 80

func getOriginalDstPort(conn *net.TCPConn) (uint16, error) {
	sysConn, err := conn.SyscallConn()
	if err != nil {
		return 0, errors.WithMessage(err, "SyscallConn error")
	}
	var port uint16
	var ierr error
	err = sysConn.Control(func(fd uintptr) {
		mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			ierr = errors.WithMessage(err, "get SO_ORIGINAL_DST error")
			return
		}
		ierr = nil
		port = uint16(mreq.Multiaddr[2])<<8 | uint16(mreq.Multiaddr[3])
	})
	if err != nil {
		return 0, errors.WithMessage(err, "SyscallConn.Control error")
	}
	if ierr != nil {
		tmp := strings.Split(conn.LocalAddr().String(), ":")
		if len(tmp) == 2 {
			port, err := strconv.ParseUint(tmp[1], 10, 16)
			if err != nil {
				return 0, errors.WithMessage(err, "get local addr port err")
			}
			return uint16(port), nil
		} else {
			return 0, errors.Errorf("local addr no port: %s", conn.LocalAddr())
		}
	}
	return port, ierr
}

func trans(left net.Conn) {
	var right net.Conn
	defer func() {
		left.Close()
		if right != nil {
			right.Close()
		}
	}()
	src := left.RemoteAddr().String()
	log.Printf("start session %s\n", src)
	var buff bytes.Buffer
	host, err := readSNIHost(io.TeeReader(left, &buff))
	if err != nil {
		log.Printf("[ERR] get sni host err: %v\n", err)
		return
	}
	port, err := getOriginalDstPort(left.(*net.TCPConn))
	if err != nil {
		log.Printf("[ERR] get origin port err: %v\n", err)
		return
	}

	var address string
	if *_useLocalDns {
		ip, err := _resolver.LookupHost(context.Background(), host)
		if err != nil {
			log.Printf("forward: 解析dns错误: %v\n", err)
			return
		}
		if len(ip) == 0 {
			log.Printf("forward: 解析dns返回0个ip\n")
			return
		}
		address = fmt.Sprintf("%s:%d", ip[0], port)
		log.Printf("forward: %s:%d[%s]\n", host, port, address)
	} else {
		address = fmt.Sprintf("%s:%d", host, port)
		log.Printf("forward %s\n", address)
	}
	dialer, purl := getProxyDialer()
	log.Printf("forward: %s:%d[%s], proxy: %s\n", host, port, address, purl)
	right, err = dialer.Dial("tcp", address)
	if err != nil {
		log.Printf("[ERR] socks to %s error: %v\n", address, err)
		return
	}
	quit := make(chan struct{})
	go func() {
		_, _ = io.Copy(right, io.MultiReader(&buff, left))
		quit <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(left, right)
		quit <- struct{}{}
	}()
	<-quit
	log.Printf("%s -> %s session quit\n", src, address)
}

func getProxyDialer() (socks.Dialer, string) {
	_lock.Lock()
	defer _lock.Unlock()
	if time.Now().After(_latest.Add(10 * time.Minute)) {
		_latest = time.Now()
		_index += 1
	}
	log.Printf("使用代理索引: %d\n", _index)
	return _proxiesDialer[_index%len(_proxiesDialer)], _proxiesUrl[_index%len(_proxiesUrl)]
}

func initProxyDialer(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return errors.WithMessage(err, "open porxies josn file err")
	}
	cfg := ProxiesConfig{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return errors.WithMessage(err, "parse porxies json file err")
	}
	for _, purl := range cfg.Proxies {
		u, err := url.Parse(purl)
		if err != nil {
			return errors.WithMessagef(err, "parse proxy url [%s] error", purl)
		}
		dialer, err := socks.FromURL(u, _tunnelDialer)
		if err != nil {
			return errors.WithMessagef(err, "proxy url [%s] to socks dialer error", purl)
		}
		_proxiesDialer = append(_proxiesDialer, dialer)
		_proxiesUrl = append(_proxiesUrl, purl)
	}
	if len(_proxiesDialer) == 0 {
		return errors.New("proxies null")
	}
	return nil
}

func switchHandler(w http.ResponseWriter, req *http.Request) {
	_lock.Lock()
	defer _lock.Unlock()

	_index += 1
	fmt.Fprintf(w, "替换代理: %s", _proxiesUrl[_index%len(_proxiesUrl)])
}

func httpServer() {
	http.HandleFunc("/switch_proxy", switchHandler)
	log.Fatal(http.ListenAndServe(":8888", nil))
}

func main() {
	flag.Parse()

	if len(*_tunnelUrl) > 0 {
		u, err := url.Parse(*_tunnelUrl)
		if err != nil {
			log.Fatal("解析本地加速代理url错误, 不应该发生")
			os.Exit(-1)
		}
		_tunnelDialer, err = socks.FromURL(u, nil)
		if err != nil {
			log.Fatal("生成本地加速代理Dialer错误, 不应该发生")
			os.Exit(-1)
		}
	}

	if err := initProxyDialer(*_proxiesFile); err != nil {
		log.Fatalf("init porxies error: %v\n", err)
		return
	}

	go httpServer()

	listener, err := net.Listen("tcp4", *_listenAddress)
	if err != nil {
		log.Fatalf("listen falt: %v", err)
		return
	}

	log.Printf("listen on %s", *_listenAddress)
	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("[ERR] accept error: %v, retry: %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			log.Fatalf("accept falt: %v", err)
		}
		go trans(conn)
	}
}

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"syscall"
	"time"

	"github.com/pkg/errors"
	socks "golang.org/x/net/proxy"
)

var _listenAddress = flag.String("listen", ":443", "listen adress:port")
var _proxyUrl = flag.String("proxy", "socks5://127.0.0.1:1080", "proxy url")
var _proxyDialer socks.Dialer

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
	address := fmt.Sprintf("%s:%d", host, port)
	log.Printf("forward %s\n", address)
	right, err = _proxyDialer.Dial("tcp", address)
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

func initProxyDialer(proxyUrl string) error {
	u, err := url.Parse(proxyUrl)
	if err != nil {
		return errors.WithMessage(err, "parse proxy url error")
	}
	dialer, err := socks.FromURL(u, nil)
	if err != nil {
		return errors.WithMessage(err, "proxy url to socks dialer error")
	}
	_proxyDialer = dialer
	return nil
}

func main() {
	flag.Parse()

	if err := initProxyDialer(*_proxyUrl); err != nil {
		log.Fatalf("init porxy dialer error: %v\n", err)
		return
	}

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

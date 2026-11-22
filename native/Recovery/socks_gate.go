package transports

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

func serveSOCKSGate(ctx context.Context, listener net.Listener, target string) {
	limit := make(chan struct{}, 64)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case limit <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		go func() {
			defer func() { <-limit }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			requested, err := socksTarget(conn)
			if err != nil {
				return
			}
			if requested != target {
				conn.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
			if err != nil {
				conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()
			if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
				return
			}
			conn.SetDeadline(time.Time{})
			copyStream(ctx, conn, remote)
		}()
	}
}

func socksTarget(conn net.Conn) (string, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", err
	}
	if header[0] != 5 || header[1] == 0 {
		return "", errors.New("SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		conn.Write([]byte{5, 255})
		return "", errors.New("SOCKS authentication")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		return "", err
	}
	if request[0] != 5 || request[1] != 1 || request[2] != 0 {
		return "", errors.New("SOCKS command")
	}
	var host string
	switch request[3] {
	case 1, 4:
		size := 4
		if request[3] == 4 {
			size = 16
		}
		ip := make([]byte, size)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", err
		}
		host = net.IP(ip).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return "", err
		}
		name := make([]byte, int(n[0]))
		if _, err := io.ReadFull(conn, name); err != nil {
			return "", err
		}
		host = string(name) // exact comparison, never resolve an untrusted destination
	default:
		return "", errors.New("SOCKS address")
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

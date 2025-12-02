package middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/davidthuman/service-spoof/internal/fingerprint"
)

type TlsClientHelloListener struct {
	net.Listener
}

func (wl *TlsClientHelloListener) Accept() (net.Conn, error) {
	conn, err := wl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &TlsClientHelloConn{Conn: conn}, nil
}

type TlsClientHelloConn struct {
	net.Conn
	buffer        bytes.Buffer
	handshakeSize uint16
	fingerprint   string
}

func (c *TlsClientHelloConn) hasCompletedClientHello() bool {
	bufLen := c.buffer.Len()
	if bufLen == 0 || c.handshakeSize == 0 {
		return false
	}
	if bufLen < int(c.handshakeSize) {
		return false
	}
	if bufLen > int(c.handshakeSize) {
		// if buffer content is longer than we need,
		// cut it to expected len
		c.buffer.Truncate(int(c.handshakeSize))
		log.Printf("truncated buffer from %d to %d bytes", bufLen, c.handshakeSize)
	}
	return true
}

func (c *TlsClientHelloConn) ParseClientHello() error {
	if c.hasCompletedClientHello() {
		return nil
	}

	bufBytes := c.buffer.Bytes()
	bufLen := c.buffer.Len()
	if bufLen < 5 {
		log.Printf("buffer too short (%d bytes), skipping parse", bufLen)
		return errors.New("incomplete client hello")
	}

	recType := bufBytes[0]
	if recType != 0x16 {
		return fmt.Errorf("tls record type 0x%x is not a handshake", recType)
	}

	vers := uint16(bufBytes[1])<<8 | uint16(bufBytes[2])
	if vers < tls.VersionSSL30 || vers > tls.VersionTLS13 {
		return fmt.Errorf("unknown tls version: 0x%x", vers)
	}

	handshakeLen := uint16(bufBytes[3])<<8 | uint16(bufBytes[4])
	c.handshakeSize = 5 + handshakeLen

	if c.hasCompletedClientHello() {
		return nil
	} else {
		return nil
	}
}

func (c *TlsClientHelloConn) Read(p []byte) (int, error) {
	// Read data from the underlying connection
	n, err := c.Conn.Read(p)

	if c.fingerprint == "" && err == nil && n > 0 {

		if c.hasCompletedClientHello() {
			//log.Println("Conn has full Client Hello message")
			//log.Println("Raw data received")
			//fmt.Println(hex.Dump(c.buffer.Bytes()))
			fingerprint1, err := fingerprint.ParseJA4(c.buffer.Bytes(), byte('t'))
			if err != nil {
				fingerprint1 = err.Error()
			}
			log.Printf("JA4 Fingerprint 1: %s\n", fingerprint1)

			fingerprint2 := ""
			j := fingerprint.JA4Fingerprint{}
			err = j.UnmarshalBytes(c.buffer.Bytes(), 't')
			if err != nil {
				fingerprint2 = err.Error()
			} else {
				fingerprint2 = j.String()
			}
			log.Printf("JA4 Fingerprint 2: %s\n", fingerprint2)

			c.fingerprint = fingerprint1

		} else {
			c.buffer.Write(p[:n])
			_ = c.ParseClientHello()
			log.Printf("Writing to buffer. New length %d", c.buffer.Len())
		}
	}

	return n, err
}

func ConnContextFingerprint(ctx context.Context, conn net.Conn) context.Context {
	log.Println("Conn Context checking connection")

	// Now assert the type to get *tls.Conn
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Use tlsConn for TLS-specific operations
		cc := tlsConn.NetConn().(*TlsClientHelloConn)
		return context.WithValue(ctx, fingerprint.JA4, &cc.fingerprint)
	} else {
		cc := conn.(*TlsClientHelloConn)
		return context.WithValue(ctx, fingerprint.JA4, &cc.fingerprint)
	}
}

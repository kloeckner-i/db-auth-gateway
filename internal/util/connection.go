package util

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Juan Batiz-Benet
 * Copyright (2) 2021 Kloeckner.I
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

import (
	"context"
	"net"
	"time"
)

// CancellableConnection is a context.Context aware network connection.
type CancellableConnection struct {
	ctx  context.Context
	conn net.Conn
}

type ioret struct {
	n   int
	err error
}

// MakeCancellable converts a net.Conn into a cancellable connection.
func MakeCancellable(ctx context.Context, conn net.Conn) *CancellableConnection {
	return &CancellableConnection{ctx, conn}
}

// Read reads an array of bytes from the connection.
func (cc *CancellableConnection) Read(p []byte) (int, error) {
	c := make(chan ioret, 1)

	buf := make([]byte, len(p))

	performRead := func() {
		n, err := cc.conn.Read(buf)
		c <- ioret{n, err}
		close(c)
	}

	go performRead()

	select {
	case ret := <-c:
		copy(p, buf)

		return ret.n, ret.err
	case <-cc.ctx.Done():
		return 0, cc.ctx.Err()
	}
}

// Write writes an array of bytes to the connection.
func (cc *CancellableConnection) Write(p []byte) (int, error) {
	c := make(chan ioret, 1)

	buf := make([]byte, len(p))
	copy(buf, p)

	go func() {
		n, err := cc.conn.Write(buf)
		c <- ioret{n, err}
		close(c)
	}()

	select {
	case r := <-c:
		return r.n, r.err
	case <-cc.ctx.Done():
		return 0, cc.ctx.Err()
	}
}

// Close closes the connection.
func (cc *CancellableConnection) Close() error {
	return cc.conn.Close()
}

// LocalAddr returns the local network address.
func (cc *CancellableConnection) LocalAddr() net.Addr {
	return cc.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (cc *CancellableConnection) RemoteAddr() net.Addr {
	return cc.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (cc *CancellableConnection) SetDeadline(t time.Time) error {
	return cc.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
func (cc *CancellableConnection) SetReadDeadline(t time.Time) error {
	return cc.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
func (cc *CancellableConnection) SetWriteDeadline(t time.Time) error {
	return cc.conn.SetWriteDeadline(t)
}

package boxtransport

import (
	"net"
	"time"
)

/*
 This file implements the methods of net.Conn for BoxConnn
*/

// Write bytes to stream
func (c *BoxConn) Write(b []byte) (n int, err error) {
	cnt := make(chan int)
	c.outStream <- &writeRequest{msg: b, n: cnt}
	for n < len(b) {
		select {
		case err = <-c.errors:
		case m := <-cnt:
			n += m
		}
	}
	return
}

// Read bytes from stream
func (c *BoxConn) Read(b []byte) (int, error) {
	if c.plain.Len() > 0 {
		return c.plain.Read(b)
	}
	msg, err := c.ReadFrame()
	if err != nil {
		return 0, err
	}
	c.plain.Write(msg)
	return c.plain.Read(b)
}

// Close BoxConn
func (c *BoxConn) Close() error {
	err := c.conn.Close()
	if err != nil {
		return err
	}
	close(c.inBox)
	close(c.outBox)
	close(c.outStream)
	select {
	case err := <-c.errors:
		return err
	default:
	}
	return nil
}

// Passthough to lower level

func (c *BoxConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *BoxConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *BoxConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *BoxConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *BoxConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

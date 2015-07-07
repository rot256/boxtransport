package boxtransport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"time"
)

/*
 Contains helper structures and methods not visible outside the package.
 Primarily reading and writing routines.
*/

type writeRequest struct {
	msg []byte
	n   chan int
}

// Frames raw data and writes to socket
func (c *BoxConn) boxWriter() {
	tmp := make([]byte, MaxRawData+LenFieldSize)
	for msg, ok := <-c.outBox; ok; msg, ok = <-c.outBox {
		size := len(msg)
		tmp = tmp[:size+LenFieldSize]
		binary.BigEndian.PutUint16(tmp[:LenFieldSize], uint16(size))
		copy(tmp[LenFieldSize:], msg)
		for left := tmp; len(left) > 0; {
			n, err := c.conn.Write(left)
			if err != nil {
				c.errors <- err
				return
			}
			left = left[n:]
		}
	}
}

// Reads from socket and extracts raw data from frames
func (c *BoxConn) boxReader() {
	buff := make([]byte, MaxRawData+LenFieldSize)
	buffSize := 0
	defer func() {
		recover()
	}()
	for {
		// Extract data
		if buffSize >= LenFieldSize {
			frameSize := int(binary.BigEndian.Uint16(buff[:])) + LenFieldSize
			if buffSize >= frameSize {
				tmp := make([]byte, frameSize-LenFieldSize)
				copy(tmp, buff[LenFieldSize:frameSize])
				copy(buff, buff[frameSize:buffSize])
				buffSize -= frameSize
				c.inBox <- tmp
				continue
			}
		}

		// Read more data
		n, err := c.conn.Read(buff[buffSize:])
		buffSize += n
		if err != nil {
			c.errors <- err
			return
		}
	}
}

// Adds opportunistic buffering to boxWriter
func (c *BoxConn) streamWriter() {
	frameSize := 0
	frame := make([]byte, MaxContent)
	var encMsg []byte
	var err error
	var ok bool
	var req *writeRequest
	defer func() {
		recover()
	}()
	for {
		// Read next request or attempt socket write
		if req == nil && len(encMsg) != 0 {
			select {
			case req, ok = <-c.outStream:
				if !ok {
					return
				}
			case c.outBox <- encMsg:
				encMsg = nil
				frameSize = 0
			}
		} else if len(encMsg) != 0 {
			c.outBox <- encMsg
			encMsg = nil
			frameSize = 0
		} else {
			req, ok = <-c.outStream
			if !ok {
				return
			}
		}

		// Copy data into frame
		if req != nil && MaxContent-frameSize > 0 {
			n := copy(frame[frameSize:], req.msg)
			req.n <- n
			req.msg = req.msg[n:]
			frameSize += n
			encMsg = nil
			if len(req.msg) == 0 {
				req = nil
			}
		}

		// Wait a little for more content (if needed)
		if MaxContent-frameSize > 0 {
			if len(c.outStream) > 0 {
				continue
			}
			time.Sleep(c.holdTime)
			if len(c.outStream) > 0 {
				continue
			}
		}

		// Seal message to send
		if frameSize > 0 && encMsg == nil {
			encMsg, err = c.seal(frame[:frameSize])
			if err != nil {
				c.errors <- err
				return
			}
		}
	}
}

// Seals data
func (c *BoxConn) seal(b []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	n, err := rand.Read(nonce[:])
	if err != nil || n != NonceSize {
		return nil, errors.New("Failed to generate nonce")
	}
	return box.SealAfterPrecomputation(nonce[:], b, &nonce, c.sharedSecret), nil
}

// Unseals and verifies data
func (c *BoxConn) unseal(b []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	copy(nonce[:], b[:NonceSize])
	plain, valid := box.OpenAfterPrecomputation(nil, b[NonceSize:], &nonce, c.sharedSecret)
	if !valid {
		return nil, errors.New("Recieved invalid box")
	}
	return plain, nil
}

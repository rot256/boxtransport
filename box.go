package boxtransport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"net"
	"time"
)

type BoxConn struct {
	// Underlying network connection
	conn net.Conn

	// Outgoing messages
	outStream chan []byte
	outBox    chan []byte
	inBox     chan []byte
	errors    chan error

	// Holds decrypted data to be read
	plain bytes.Buffer

	// Box keys
	sharedSecret   *[32]byte
	privateKey     *[32]byte
	publicKey      *[32]byte
	peersPublicKey *[32]byte
}

const (
	LenFieldSize = 2                                     // Length field size
	NonceSize    = 24                                    // Size of box nonce
	MaxRawData   = (1 << 16) - 1                         // Maximum raw data in frame (content + nonce + overhead)
	MaxContent   = MaxRawData - box.Overhead - NonceSize // Maximum encrypted content in frame
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Wrap a connection in a new BoxTranport
func NewBoxConn(conn net.Conn, publickey, privateKey, peersPublicKey *[32]byte) (*BoxConn, error) {
	// Prepare buffers
	c := &BoxConn{}
	c.conn = conn

	// Prepare reader and writer
	c.inBox = make(chan []byte)
	c.outBox = make(chan []byte)
	c.outStream = make(chan []byte)
	c.errors = make(chan error, 5)
	go c.boxReader()
	go c.boxWriter()
	go c.streamWriter()

	// Prepare keys
	c.peersPublicKey = peersPublicKey
	c.publicKey = publickey
	c.privateKey = privateKey
	if c.privateKey == nil {
		return nil, errors.New("Local private key must be specified")
	} else if c.publicKey == nil {
		return nil, errors.New("Local public key must be specifed")
	}

	// Send public key (unencrypted)
	c.outBox <- c.publicKey[:]

	// Recieve peers public key
	select {
	case err := <-c.errors:
		return nil, err
	case msg := <-c.inBox:
		if len(msg) != 32 {
			return nil, errors.New("Recieved invalid public key")
		} else if c.peersPublicKey == nil {
			c.peersPublicKey = &[32]byte{}
			copy(c.peersPublicKey[:], msg)
		} else if !bytes.Equal(msg, c.peersPublicKey[:]) {
			return nil, errors.New("Expected diffrent public key")
		}
	}

	// Compute shared secret
	c.sharedSecret = &[32]byte{}
	box.Precompute(c.sharedSecret, c.peersPublicKey, c.privateKey)
	return c, nil
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
	var nextMsg []byte
	var encMsg []byte
	var err error
	var ok bool
	defer func() {
		recover()
	}()
	for {
		// Read more data or attempt socket write
		if len(nextMsg) == 0 && len(encMsg) != 0 {
			select {
			case nextMsg, ok = <-c.outStream:
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
			nextMsg, ok = <-c.outStream
			if !ok {
				return
			}
		}

		// Copy data into frame
		if len(nextMsg) != 0 && MaxContent-frameSize > 0 {
			n := copy(frame[frameSize:], nextMsg)
			nextMsg = nextMsg[n:]
			frameSize += n
			encMsg = nil
		}

		// Seal message
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

// Send a frame manually
func (c *BoxConn) WriteFrame(frame []byte) error {
	if len(frame) > MaxContent {
		return errors.New("Frame too large!")
	}
	enc, err := c.seal(frame)
	if err != nil {
		return err
	}
	select {
	case err := <-c.errors:
		return err
	case c.outBox <- enc:
	}
	return nil
}

// Read next frame
func (c *BoxConn) ReadFrame() ([]byte, error) {
	select {
	case err := <-c.errors:
		return nil, err
	case msg := <-c.inBox:
		return c.unseal(msg)
	}
	return nil, nil
}

// Write bytes to stream
func (c *BoxConn) Write(b []byte) (n int, err error) {
	m := min(len(b), MaxContent)
	for m > 0 {
		select {
		case err = <-c.errors:
			return
		case c.outStream <- b[:m]:
			n += m
			b = b[m:]
			m = min(len(b), MaxContent)
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

// Read and return excactly n bytes from the stream
func (c *BoxConn) ReadN(n int) (b []byte, err error) {
	b = make([]byte, n)
	for tmp := b; len(tmp) > 0 && err == nil; {
		n, err = c.Read(tmp)
		tmp = tmp[n:]
	}
	return b, err
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

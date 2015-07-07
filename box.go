package boxtransport

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/nacl/box"
	"net"
	"time"
)

/*
 This file defines the underlying BoxConn structure 
 and available functions not declared in an interface.
*/

type BoxConn struct {
	// Underlying network connection
	conn net.Conn

	// Outgoing messages
	outStream chan *writeRequest
	outBox    chan []byte
	inBox     chan []byte
	errors    chan error
	
	// Settings
	holdTime time.Duration

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


// Wrap a connection in a new BoxTranport
func NewBoxConn(conn net.Conn, publickey, privateKey, peersPublicKey *[32]byte) (*BoxConn, error) {
	// Prepare buffers
	c := &BoxConn{}
	c.conn = conn
	c.holdTime = time.Microsecond * 10

	// Prepare reader and writer
	c.inBox = make(chan []byte)
	c.outBox = make(chan []byte)
	c.outStream = make(chan *writeRequest, 10)
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

// Set hold time (time to wait for additional write calls) [10 microsecs]
func (c *BoxConn) SetHoldtime(t time.Duration) {
	c.holdTime = t
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

// Read and return excactly n bytes from the stream
func (c *BoxConn) ReadN(n int) (b []byte, err error) {
	b = make([]byte, n)
	for tmp := b; len(tmp) > 0 && err == nil; {
		n, err = c.Read(tmp)
		tmp = tmp[n:]
	}
	return b, err
}

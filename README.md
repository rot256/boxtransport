BoxTransport
============
------------

BoxTransport contains implementation of the [net.Conn](https://golang.org/pkg/net/#Conn) interface which allows for encrypted communication over TCP using NaCl boxes called BoxConn.  BoxConn can be used for streaming content (using the net.Conn interface).

BoxConn also has a .WriteFrame and .ReadFrame method which allows sending fixed size messages. Frames are limited to 65495 bytes (BoxTransport.MaxContent) - streaming have no such limitations.

A new BoxTransport can be created like this:

    secure, err := NewBoxConn(conn net.Conn, publickey, privateKey, peersPublicKey *[32]byte (*BoxTransport, error)

if peersPublicKey is nil any public key given by the other side will be accepted (can be used by a server where the clients don't authenticate). BoxConn implements  [net.Conn](https://golang.org/pkg/net/#Conn), below are examples of the methods not declared in the interface but available in BoxConn:

    err := secure.WriteFrame([]byte("Single frame"))
    data, err := secure.ReadFrame()
    fmt.Println("Got a new frame:", data, err)

There is also a new function for streaming content (on the off chance that it might useful):

    data, err := secure.ReadN(5)
    fmt.Println("Here are exactly 5 bytes:", data, err)

### The protocol

Every frame starts with the length of the message to follow:

    Length | Content

The first frame contains exactly 32 bytes which are senders public key (can then be accepted or discarded by the receiver based on peersPublicKey). All subsequent messages will contain NaCl boxes in the content field.

    Nonce | Box

The nonce is randomly generated.

### Q & A

> Q : Can I wrap a BoxTransport in a BoxTransport? (Onion encryption)
> A : Yes (be aware of the overhead though)




Q : Is every Write in it's own NaCl box?

A : No, BoxTransport attempts to combine multiple writes into a single frame.




Q : Can I mix .ReadFrame with the .Write method?

A : You can but it is probably a bad idea (see previous question).

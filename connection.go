package telnet

import (
	"fmt"
	"net"
)

// Negotiator defines the requirements for a telnet option handler.
type Negotiator interface {
	// OptionCode returns the 1-byte option code that indicates this option.
	OptionCode() byte
	// Offer is called when a new connection is initiated. It offers the handler
	// an opportunity to advertise or request an option.
	Offer(conn *Connection)
	// HandleDo is called when an IAC DO command is received for this option,
	// indicating the client is requesting the option to be enabled.
	HandleDo(conn *Connection)
	// HandleWill is called when an IAC WILL command is received for this
	// option, indicating the client is willing to enable this option.
	HandleWill(conn *Connection)
	// HandleSB is called when a subnegotiation command is received for this
	// option. body contains the bytes between `IAC SB <OptionCode>` and `IAC
	// SE`.
	HandleSB(conn *Connection, body []byte)
}

// Connection to the telnet server. This lightweight TCPConn wrapper handles
// telnet control sequences transparently in reads and writes, and provides
// handling of supported options.
type Connection struct {
	// The underlying network connection.
	net.Conn

	// OptionHandlers handle IAC options; the key is the IAC option code.
	OptionHandlers map[byte]Negotiator

	// Read buffer
	buf  []byte
	r, w int // buf read and write positions

	// IAC handling
	iac    bool
	cmd    byte
	option byte

	// Known client wont/dont
	clientWont map[byte]bool
	clientDont map[byte]bool
}

// NewConnection initializes a new Connection for this given TCPConn. It will
// register all the given Option handlers and call Offer() on each, in order.
func NewConnection(c net.Conn, options []Option) *Connection {
	conn := &Connection{
		Conn:           c,
		OptionHandlers: make(map[byte]Negotiator, len(options)),
		buf:            make([]byte, 256),
		clientWont:     make(map[byte]bool),
		clientDont:     make(map[byte]bool),
	}
	for _, o := range options {
		h := o(conn)
		conn.OptionHandlers[h.OptionCode()] = h
		h.Offer(conn)
	}
	return conn
}

// Write to the connection, escaping IAC as necessary.
func (c *Connection) Write(b []byte) (n int, err error) {
	var nn, lastWrite int
	for i, ch := range b {
		if ch == IAC {
			if lastWrite < i-1 {
				nn, err = c.Conn.Write(b[lastWrite:i])
				n += nn
				if err != nil {
					return
				}
			}
			lastWrite = i + 1
			nn, err = c.Conn.Write([]byte{IAC, IAC})
			n += nn
			if err != nil {
				return
			}
		}
	}
	if lastWrite < len(b) {
		nn, err = c.Conn.Write(b[lastWrite:])
		n += nn
	}
	return
}

// RawWrite writes raw data to the connection, without escaping done by Write.
// Use of RawWrite over Conn.Write allows Connection to do any additional
// handling necessary, so long as it does not modify the raw data sent.
func (c *Connection) RawWrite(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}

const maxReadAttempts = 10

// Read from the connection, transparently removing and handling IAC control
// sequences. It may attempt multiple reads against the underlying connection if
// it receives back only IAC which gets stripped out of the stream.
func (c *Connection) Read(b []byte) (n int, err error) {
	for i := 0; i < maxReadAttempts && n == 0 && len(b) > 0; i++ {
		n, err = c.read(b)
	}
	return
}

// read reads data from the Connection into the provided byte slice.
func (c *Connection) read(b []byte) (n int, err error) {
	// Fill the buffer with data from the connection
	err = c.fill(len(b))
	if err != nil {
		return
	}

	lastWrite := 0     // Track the last index written in the byte slice
	var ignoreIAC bool // Flag to ignore IAC sequence

	// write is a helper function to copy data from the Connection's buffer to the byte slice
	write := func(end int) int {
		// If the read index is at the end, return 0
		if c.r == end {
			return 0
		}
		// Copy data from the Connection's buffer to the byte slice
		nn := copy(b[lastWrite:], c.buf[c.r:end])
		n += nn
		lastWrite += nn
		c.r += nn
		return nn
	}

	// endIAC resets the IAC sequence variables and sets the read index to the provided value
	endIAC := func(i int) {
		c.iac = false
		c.cmd = 0
		c.option = 0
		c.r = i + 1
	}

	// Iterate over the buffer and copy data to the byte slice
	for i := c.r; i < c.w && lastWrite < len(b); i++ {
		ch := c.buf[i]

		// Check for IAC sequence
		if ch == IAC && !ignoreIAC {
			if c.iac && c.cmd == 0 {
				// Escaped IAC in text, copy the data and move the read index
				write(i)
				c.r++
				c.iac = false
				continue
			} else if c.iac && c.buf[i-1] == IAC {
				// Escaped IAC inside IAC sequence, remove the escaped IAC and set the ignore flag
				copy(c.buf[:i], c.buf[i+1:])
				i--
				ignoreIAC = true
				continue
			} else if !c.iac {
				// Start of IAC sequence, copy the data and set the iac flag
				write(i)
				c.iac = true
				continue
			}
		}

		ignoreIAC = false

		if c.iac && c.cmd == 0 {
			// Handle IAC command
			c.cmd = ch
			if ch == SB {
				// Handle SB command, check if there is enough data in the buffer
				if i+2 >= c.w {
					break
				}
				c.r = i + 2
			}
			continue
		} else if c.iac && c.option == 0 {
			// Handle IAC option
			c.option = ch
			if c.cmd != SB {
				// Handle negotiation and reset IAC sequence
				if _, err := c.handleNegotiation(); err != nil {
					return 0, err
				}
				endIAC(i)
			}
			continue
		} else if c.iac && c.cmd == SB && ch == SE && c.buf[i-1] == IAC {
			// Handle SB command with SE option
			if h, ok := c.OptionHandlers[c.option]; ok {
				h.HandleSB(c, c.buf[c.r:i-1])
			}
			// Reset IAC sequence
			endIAC(i)
			continue
		}

	}

	// Copy remaining data from the buffer to the byte slice
	nn := copy(b[lastWrite:], c.buf[c.r:c.w])
	n += nn
	c.r += nn
	return
}

// fill reads from the connection until it has at least
// the requested number of bytes in the buffer.
func (c *Connection) fill(requestedBytes int) error {
	// If there are bytes remaining to be read in the buffer,
	// shift them to the beginning of the buffer.
	if c.r > 0 {
		copy(c.buf, c.buf[c.r:])
		c.w -= c.r
		c.r = 0
	}
	// If the buffer is not big enough to hold the requested
	// number of bytes, create a new buffer with the requested
	// size and copy the existing data into it.
	if len(c.buf) < requestedBytes {
		newBuf := make([]byte, requestedBytes)
		copy(newBuf, c.buf[c.r:c.w])
		c.buf = newBuf
		c.w = c.w - c.r
		c.r = 0
	}
	// Read from the connection into the buffer and update the
	// write pointer.
	nn, err := c.Conn.Read(c.buf[c.w:])
	c.w += nn
	return err
}

// SetWindowTitle attempts to set the client's telnet window title. Clients may
// or may not support this.
func (c *Connection) SetWindowTitle(title string) error {
	if _, err := fmt.Fprintf(c, TitleBarFmt, title); err != nil {
		return err
	}
	return nil
}

func (c *Connection) handleNegotiation() (int, error) {
	switch c.cmd {
	case WILL:
		if h, ok := c.OptionHandlers[c.option]; ok {
			h.HandleWill(c)
		} else {
			return c.writeBytes(IAC, DONT, c.option)
		}
	case WONT:
		c.clientWont[c.option] = true
	case DO:
		if h, ok := c.OptionHandlers[c.option]; ok {
			h.HandleDo(c)
		} else {
			return c.writeBytes(IAC, WONT, c.option)
		}
	case DONT:
		c.clientDont[c.option] = true
	}
	return 0, nil
}

func (c *Connection) writeBytes(bytes ...byte) (int, error) {
	return c.Conn.Write(bytes)
}

package plus_minus

import "errors"
import "encoding/binary"
import "sync"
import "sync/atomic"

type PLUS struct {
	connections map[uint64]*ConnectionState	
	mutex *sync.RWMutex
}

type ConnectionState struct {
	CAT uint64
	NextPSN uint32
	PSE uint32
	StopSentPSN uint32
	StopReceivedPSN uint32
}

const MIN_LENGTH = 20
const MAGIC = uint32(0xd8007ff)

// Indicates that the packet is too small to be a valid packet.
var ErrPacketTooSmall = errors.New("Packet too small.")

// Indicates the the magic flag is not correct (and thus this is not a PLUS packet)
var ErrInvalidMagicFlag = errors.New("Invalid magic flag.")

// Indicates that the packet is otherwise malformed. 
var ErrMalformedPacket = errors.New("Malformed packet.")

// This variable holds a reference to a cryptographically strong
// random number generator (32bits, uint32) that must be safe for
// concurrent usage. You may provide your own function but you should
// do so before invoking `Process`.
var RandF = defaultRand32

// The default random number generator.
func defaultRand32() uint32 {
	return 4
}

// Returns the state of a connection or nil if the connection does not exist.
// Safe for concurrent usage (internal lock).
func (p *PLUS) GetConnection(cat uint64) *ConnectionState {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return p.connections[cat]
}

// Creates a new connection and returns the state of the new connection.
// Safe for concurrent usage (internal lock). 
func (p *PLUS) CreateConnection(cat uint64) *ConnectionState {
	connectionState := & ConnectionState { 
		CAT : cat,
		NextPSN : RandF(),
		PSE : 0,
		StopSentPSN : 0,
		StopReceivedPSN : 0,
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.connections[cat] = connectionState

	return connectionState
}

// Write the header for the next output packet into the supplied buffer.
// Safe for concurrent use but you need one buffer for each concurrent use.
func (c *ConnectionState) Next(buf []byte) {
	mf := MAGIC << 4

	cat := atomic.LoadUint64(&c.CAT)
	psn := atomic.AddUint32(&c.NextPSN, 1)
	pse := atomic.LoadUint32(&c.PSE)

	binary.BigEndian.PutUint32(buf[0:4], mf)
	binary.BigEndian.PutUint64(buf[4:12], cat)
	binary.BigEndian.PutUint32(buf[12:16], psn)
	binary.BigEndian.PutUint32(buf[16:20], pse)
}

// Process new data (which should be a (potentially) valid plus packet). 
// It will return the state of the connection the data belongs to, and the PLUS header
// with certain fields zeroed out for integrity protection.
// and an error (or nil if no error occured). 
// Safe for concurrent use but you need a different header buffer for each concurrent use. 
// This function does not check the integrity of the PLUS header,
// just whether it's a valid PLUS header. 
func (p *PLUS) Process(buf []byte, header []byte) (*ConnectionState, []byte, bool, error) {

	if len(buf) < MIN_LENGTH {
		return nil, nil, false, ErrPacketTooSmall
	}

	mf := binary.BigEndian.Uint32(buf) // Magic (12 bits), Flags (4 bits)

	magic := mf >> 4
	flags := mf & 0x0F

	if magic != MAGIC {
		return nil, nil, false, ErrInvalidMagicFlag
	}

	cat := binary.BigEndian.Uint64(buf[4:])
	psn := binary.BigEndian.Uint32(buf[8:])
	//pse := binary.BigEndian.Uint32(buf[12:]) (unused)

	connectionState := p.GetConnection(cat)

	if flags & 0x01 == 0x00 {	// Is extended flag (X) not set?
		/* it's a basic packet */
		header = header[0:MIN_LENGTH]
		copy(header, buf[0:MIN_LENGTH])
	} else {
		/* verify extended header */
		return connectionState, nil, false, ErrMalformedPacket
	}

	// Update the PSE
	atomic.StoreUint32(&connectionState.PSE, psn)

	if flags & 0x02 != 0x00 { // Is the stop (S) flag set?
		// Overwrite the StopReceivedPSN if and only if it is zero. 
		atomic.CompareAndSwapUint32(&connectionState.StopReceivedPSN, 0, psn) 
	}

	return connectionState, header, false, nil
}

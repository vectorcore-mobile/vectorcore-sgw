package gtpu

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// GTP-U IE type values per TS 29.281 Table 19 (Table 8.1-1 in §8):
//
//	"14  | TV  | Recovery                          | 8.2"
//	"16  | TV  | Tunnel Endpoint Identifier Data I | 8.3"
//	"133 | TLV | GSN Address (GTP-U Peer Address)  | 8.4"
const (
	IETypeRecovery        uint8 = 14  // Table 19: "14  | TV  | Recovery | 8.2"
	IETypeTEIDDataI       uint8 = 16  // Table 19: "16  | TV  | Tunnel Endpoint Identifier Data I | 8.3"
	IETypeGTPUPeerAddress uint8 = 133 // Table 19: "133 | TLV | GSN Address (GTP-U Peer Address) | 8.4"
)

// BuildRecovery builds a Recovery IE per TS 29.281 §8.2.
// TV format: Type(1 byte) + Value(1 byte).
// Per §7.2.2: "The Restart Counter value in the Recovery information element shall not be
// used, i.e. it shall be set to zero by the sender."
func BuildRecovery() []byte {
	return []byte{IETypeRecovery, 0x00}
}

// BuildTEIDDataI builds a Tunnel Endpoint Identifier Data I IE per TS 29.281 §8.3.
// TV format: Type(1 byte) + TEID(4 bytes big-endian).
// §8.3: "The Tunnel Endpoint Identifier Data I information element contains the Tunnel
// Endpoint Identifier used by a GTP entity for the user plane."
func BuildTEIDDataI(teid uint32) []byte {
	b := make([]byte, 5)
	b[0] = IETypeTEIDDataI
	binary.BigEndian.PutUint32(b[1:5], teid)
	return b
}

// BuildGTPUPeerAddressIPv4 builds a GTP-U Peer Address IE for an IPv4 address per §8.4.
// TLV format: Type(1 byte) + Length(2 bytes) + IPv4(4 bytes).
// §8.4: "The Length field may have only two values (4 or 16) depending on whether the
// GTP-U peer address is IPv4 or IPv6."
func BuildGTPUPeerAddressIPv4(ip netip.Addr) ([]byte, error) {
	if !ip.Is4() {
		return nil, fmt.Errorf("gtpu: BuildGTPUPeerAddressIPv4 requires an IPv4 address")
	}
	b := make([]byte, 7) // 1 (type) + 2 (length) + 4 (IPv4)
	b[0] = IETypeGTPUPeerAddress
	binary.BigEndian.PutUint16(b[1:3], 4) // length = 4 for IPv4 per §8.4
	a4 := ip.As4()
	copy(b[3:7], a4[:])
	return b, nil
}

// ParseIEs parses GTP-U signalling message IEs from b and returns a map of IE type → value bytes.
// Supports TV (type < 128) and TLV (type >= 128) formats per §8.1 and Table 19.
// Unknown TV IE lengths halt parsing; unknown TLV IEs are skipped via their length field.
func ParseIEs(b []byte) map[uint8][]byte {
	result := make(map[uint8][]byte)
	i := 0
	for i < len(b) {
		t := b[i]
		i++
		if t >= 128 {
			// TLV format: 2-byte length field follows type.
			if i+2 > len(b) {
				break
			}
			l := int(binary.BigEndian.Uint16(b[i : i+2]))
			i += 2
			if i+l > len(b) {
				break
			}
			result[t] = b[i : i+l]
			i += l
		} else {
			// TV format: fixed length determined by type per Table 19.
			var vlen int
			switch t {
			case IETypeRecovery:
				vlen = 1 // §8.2: 1-byte restart counter
			case IETypeTEIDDataI:
				vlen = 4 // §8.3: 4-byte TEID
			default:
				break // unknown TV IE: cannot advance, stop parsing
			}
			if vlen == 0 {
				break
			}
			if i+vlen > len(b) {
				break
			}
			result[t] = b[i : i+vlen]
			i += vlen
		}
	}
	return result
}

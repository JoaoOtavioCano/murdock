package main

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

type idGenerator interface {
	generateId() []byte
}

// Id generator that implements the UUIDv7 RFC 9562 specification
// https://datatracker.ietf.org/doc/rfc9562/
type UUIDv7Generator struct{}

func (g *UUIDv7Generator) generateId() []byte{
	uuid := make([]byte, 16)
	
	// Timestamp in Unix milliseconds
	unixMs := uint64(time.Now().UnixMilli())
	unixMs = unixMs << 16
	binary.BigEndian.PutUint64(uuid[0:8], unixMs) // Put into first 8 bytes, we only care about first 6

	// Version is equal 7 but using only the four most significant bits
	version := 0b0111 << 4

	// Variant is equal 2 but using only the two most significant bits
	variant := 0b10 << 6

	// 74 bits random bits necessary = 12 bits after version + 62 bits after variant
	// Generating 80 random bits.
	// No error handling because Go garantees Read always succeeds.
	randomBits := make([]byte, 10)
	rand.Read(randomBits)
	
	copy(uuid[6:], randomBits)
	uuid[6] = uuid[6] & 0b00001111 // clean the 4 most singnificant bits
	uuid[6] = uuid[6] | byte(version)
	uuid[8] = uuid[8] & 0b00111111 // clean the 2 most singnificant bits
	uuid[8] = uuid[8] | (byte(variant) << 0)

	return uuid
}


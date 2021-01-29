package main

import (
	"fmt"
	"testing"
)

// TestParseFlags test it
func TestParseFlags(t *testing.T) {
	msg := DNSMsgHdr{
		ID:      0,
		FLAGS:   0x8180,
		QDCOUNT: 0,
		ANCOUNT: 0,
		NSCOUNT: 0,
		ARCOUNT: 0,
	}
	fmt.Println(msg.parseFlags())
}

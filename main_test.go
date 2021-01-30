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

func TestParseDNSMsgHdr(t *testing.T) {
	var testData []byte = []byte{
		0x6a, 0x6c,
		0x81, 0x80,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
	}

	dnsMsgHdr := parseDNSHdr(testData)
	flags := dnsMsgHdr.parseFlags()
	fmt.Println(dnsMsgHdr, flags)
}

func TestInitDNSHosts(t *testing.T) {
	dnsHosts := initDNSHosts()
	for k, v := range dnsHosts {
		fmt.Printf("key(%s): value(%s)\n", k, v)
	}
}

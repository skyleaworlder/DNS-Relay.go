package main

import (
	"fmt"
	"testing"
)

// TestParseFlags test it
func TestParseFlags(t *testing.T) {
	fmt.Println("TestParseFlags:")
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
	fmt.Println("TestParseDNSMsgHdr:")
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

func TestParseDNSQst(t *testing.T) {
	fmt.Println("TestParseDNSQst:")
	var testData []byte = []byte{
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	dnsMsgQst := parseDNSQst(testData)
	fmt.Println(dnsMsgQst, dnsMsgQst.QNAME, dnsMsgQst.QTYPE, dnsMsgQst.QCLASS)
}

func TestParseDNSRequest(t *testing.T) {
	fmt.Println("TestParseDNSRequest:")
	var testData []byte = []byte{
		0x6a, 0xec,
		0x81, 0x80,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	dnsMsgHdr, dnsMsgQst := parseDNSRequest(testData)
	fmt.Println(dnsMsgHdr.ID, dnsMsgHdr.parseFlags(), dnsMsgHdr.QDCOUNT, dnsMsgHdr.ANCOUNT, dnsMsgHdr.NSCOUNT, dnsMsgHdr.ARCOUNT)
	fmt.Println(dnsMsgQst.QNAME, dnsMsgQst.QTYPE, dnsMsgQst.QCLASS)
}

func TestInitDNSHosts(t *testing.T) {
	fmt.Println("TestInitDNSHosts:")
	dnsHosts := initDNSHosts()
	for k, v := range dnsHosts {
		fmt.Printf("key(%s): value(%s)\n", k, v)
	}
}

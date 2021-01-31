package main

import (
	"fmt"
	"net"
	"os"
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

// TestParseDomainName
func TestParseDomainName(t *testing.T) {
	fmt.Println("TestParseDomainName:")
	qst := DNSMsgQst{
		QNAME:  []byte{0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00},
		QCLASS: 0,
		QTYPE:  1,
	}
	fmt.Println(qst.parseDomainName())
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
	dnsMsgQst, _ := parseDNSQst(testData)
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
	dnsMsgHdr, dnsMsgQst, _ := parseDNSRequest(testData)
	fmt.Println(dnsMsgHdr.ID, dnsMsgHdr.parseFlags(), dnsMsgHdr.QDCOUNT, dnsMsgHdr.ANCOUNT, dnsMsgHdr.NSCOUNT, dnsMsgHdr.ARCOUNT)
	fmt.Println(dnsMsgQst.QNAME, dnsMsgQst.QTYPE, dnsMsgQst.QCLASS)
}

func TestComposeHdrQstAsr(t *testing.T) {
	fmt.Println("TestComposeHdrQstAsr:")
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
	dnsMsgHdr, dnsMsgQst, _ := parseDNSRequest(testData)
	dnsMsgAsr := DNSMsgRR{
		NAME:     []byte{0xc0, 0x0c},
		TYPE:     1,
		CLASS:    1,
		TTL:      19,
		RDLENGTH: 4,
		RDATA:    []byte{0x3b, 0x18, 0x03, 0xae},
	}
	resp := composeHdrQstAsr(dnsMsgHdr, dnsMsgQst, dnsMsgAsr)
	fmt.Println(len(resp), resp)
}

func TestCreateDNSMsgAsr(t *testing.T) {
	fmt.Println("TestCreateDNSMsgAsr:")
	fmt.Println(createDNSMsgAsr(1, 1, 12, 4, "192.168.10.1"))
}

func TestGetIPAddrByDomainName(t *testing.T) {
	fmt.Println("TestgetIPAddrByDomainName:")
	hosts := initDNSHosts()
	var testData []string = []string{
		"www.baidu.com", "www.bilibili.com", "www.ljg.top",
	}
	for _, dn := range testData {
		ip, _ := getIPAddrByDomainName(hosts, dn)
		fmt.Printf("ip found is %s\n", ip)
	}
}

func TestInitDNSHosts(t *testing.T) {
	fmt.Println("TestInitDNSHosts:")
	dnsHosts := initDNSHosts()
	for k, v := range dnsHosts {
		fmt.Printf("key(%s): value(%s)\n", k, v)
	}
}

func TestGoSocket(t *testing.T) {
	t.Skip("skip in test")
	var testData []byte = []byte{
		0x6a, 0xec,
		0x01, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x00, 0x00, 0x01,
	}
	fmt.Println("Go Socket test:")
	udpAddr, _ := net.ResolveUDPAddr("udp", ":80")
	fmt.Println("udpAddr.IP should be <nil>")
	fmt.Println("udpAddr ip:", udpAddr.IP, ", port:", udpAddr.Port, ", zone:", udpAddr.Zone)
	conn, _ := net.Dial("udp", "192.168.10.1:53")

	buf := make([]byte, 32)
	for i := 0; i < 5; i++ {
		_, err := conn.Write(testData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fuck!: %s", err.Error())
		}
		fmt.Println("lvelvelve:", conn.RemoteAddr())
		// result, err := ioutil.ReadAll(conn)
		_, err = conn.Read(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fuck!: %s", err.Error())
		}
		fmt.Println(string(buf), buf)
	}
}

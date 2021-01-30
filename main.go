package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// DNSMsgHdr is a struct of DNS MESSAGE Header Format
// from RFC-1035 / RFC-2535
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// QDCOUNT: the number of entries in question section (1 normal)
// ANCOUNT: the number of RR(resource records) in Answer Section (0 perhaps)
// NSCOUNT: the number of Name Server RR in the authority records (0 perhaps)
// ARCOUNT: the number of RR in Additional Records (0 perhaps)
type DNSMsgHdr struct {
	ID      uint16
	FLAGS   uint16
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

// DNSMsgFlags is a struct of DNS message header flags
// from RFC-1035 / RFC-2535
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// QR specifies msg's type: 0 => query msg; 1 => response msg
// Opcode specifies kind of QUERY: 0 => standard; 1 => inverse; 2 => server status req
// AA: authoritative answer, only valid in response msg
// TC: truncation, specifying whether length is greater than standard permitted
// RD: Recursion Desired. If it's set in a query msg, it will be copied into the response msg
// RA: Recursion Available. Name server supports recursive query if set, disabled if cleared
// Z : reserved
// AD: authentic data, specifies all the data whether authenticated by policies of that server
// CD: checking disabled, specifies whether pending data is acceptable the server solves query
// RCODE: response code, 6-15 -> reserved; 0 -> no error; 3 -> name error; 1 -> format error;
//                       2 -> server failure; 4 -> not supported; 5 -> refused
type DNSMsgFlags struct {
	QR     uint8
	Opcode uint8
	AA     uint8
	TC     uint8
	RD     uint8
	RA     uint8
	Z      uint8
	AD     uint8
	CD     uint8
	RCODE  uint8
}

// DNSMsgQst is a struct of DNS MESSAGE Question Format
// from RFC-1035
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// QNAME: domain NAME, a length octet followed by domain name octet, such as:
//    	  keepalive.softether.org => 09 keepalive 09 softether 03 org 00
// QTYPE: two octet code specifies type of query. RR TYPE contains A(1), AAAA(28)...
// QCLASS: two octet code specifies class of query. IN(Internet:1)
type DNSMsgQst struct {
	QNAME  []byte
	QTYPE  uint16
	QCLASS uint16
}

// DNSMsgRR is a struct of DNS MESSAGE Answer Format
// from RFC-1035
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// NAME: domain name, but always a pointer to a prior occurance of the same name
// TYPE: two octet about RR TYPE, specifies the meaning of the data in the RDATA
// CLASS: two octet that specifies the class of the data in the RDATA
// TTL: 32 bits, time to live.
// RDLENGTH: 16 bit integer that specifies the length of the RDATA
// RDATA: a variable length string of octets.
//
// about NAME field, it always use MESSAGE COMPRESSION to compress the space
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//    | 1  1|                OFFSET                   |
//    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// the NAME field is always C0_XX, while OFFSET begin at DNS response
// the first ANSWER SECTION's NAME field is C0_0C normally
type DNSMsgRR struct {
	NAME     []byte
	TYPE     uint16
	CLASS    uint16
	TTL      uint32
	RDLENGTH uint16
	RDATA    []byte
}

// parseFlags
func (msg DNSMsgHdr) parseFlags() (flags DNSMsgFlags) {
	flags.QR = uint8((msg.FLAGS & 0b1000000000000000) >> 15)
	flags.Opcode = uint8((msg.FLAGS & 0b0111100000000000) >> 11)
	flags.AA = uint8((msg.FLAGS & 0b0000010000000000) >> 10)
	flags.TC = uint8((msg.FLAGS & 0b0000001000000000) >> 9)
	flags.RD = uint8((msg.FLAGS & 0b0000000100000000) >> 8)
	flags.RA = uint8((msg.FLAGS & 0b0000000010000000) >> 7)
	flags.Z = uint8((msg.FLAGS & 0b0000000001000000) >> 6)
	flags.AD = uint8((msg.FLAGS & 0b0000000000100000) >> 5)
	flags.CD = uint8((msg.FLAGS & 0b0000000000010000) >> 4)
	flags.RCODE = uint8(msg.FLAGS & 0b0000000000001111)
	return
}

func parseDNSHdr(msg []byte) (dnsMsgHdr DNSMsgHdr) {
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qdcount := binary.BigEndian.Uint16(msg[4:6])
	ancount := binary.BigEndian.Uint16(msg[6:8])
	nscount := binary.BigEndian.Uint16(msg[8:10])
	arcount := binary.BigEndian.Uint16(msg[10:12])

	dnsMsgHdr = DNSMsgHdr{
		ID: id, FLAGS: flags, QDCOUNT: qdcount,
		ANCOUNT: ancount, NSCOUNT: nscount, ARCOUNT: arcount,
	}
	return
}

// parseDNSQst is a func to draw Question field from DNS MESSAGE
// DNS Question includes QNAME, QTYPE and QCLASS
// the length of QTYPE and QCLASS is a constant, while QNAME's length varies
// about QNAME, for instance, google.com
// "google.com" will be separated into 2 pieces, "google" and "com"
// since a length octet followed by domain name octet, the octet of "google.com" is:
// || 06 | 67 6f 6f 67 6c 65 || 03 | 63 6f 6d || 00 ||
// |-len-|-------google------|-len-|----com----|-00-|
// so the last octet, namely, "00" will be a separator between QNAME and QTYPE
func parseDNSQst(msg []byte) (dnsMsgQst DNSMsgQst) {
	i := 0
	for msg[i] != 0 {
		i = i + 1
	}
	// [0:i+2], as for "google.com", i = 11
	// but 06 67 6f 6f 67 6c 65 03 63 6f 6d 00, i should be 12
	qname := msg[0 : i+1]
	qtype := binary.BigEndian.Uint16(msg[i+1 : i+3])
	qclass := binary.BigEndian.Uint16(msg[i+3 : i+5])

	dnsMsgQst = DNSMsgQst{
		QNAME: qname, QTYPE: qtype, QCLASS: qclass,
	}
	return
}

func checkError(successInfo string, err error) bool {
	if err != nil {
		fmt.Fprintf(os.Stderr, "DNS-Relay> Error occur: %s\n", err.Error())
		os.Exit(1)
	} else {
		fmt.Printf("DNS-Relay> Success: %s\n", successInfo)
		return true
	}
	return false
}

// initDNSHosts is a func to generate hosts map
// this func read "hosts" to initialize hosts and return map to main_func
func initDNSHosts() (hosts map[string]string) {
	file, err := os.Open("hosts")
	checkError("open hosts config success", err)
	defer file.Close()

	rd := bufio.NewReader(file)
	hosts = make(map[string]string)
	for {
		line, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		checkError("read hosts config success", err)
		// trim \n
		dnsHostsLineArr := strings.Split(strings.Trim(line, "\n"), " ")
		// string.Split get a slice: [ip, ' ', ' ', ' ', ..., domainName]
		// len(slice)-1 to get the last element of slice
		hosts[dnsHostsLineArr[0]] = dnsHostsLineArr[len(dnsHostsLineArr)-1]
	}
	return
}

// DNSRelay is the main function
func DNSRelay() {
	// DNS run over UDP port 53
	port := ":53"
	udpAddr, err := net.ResolveUDPAddr("udp", port)
	checkError("udp construct", err)
	listen, err := net.ListenUDP("udp", udpAddr)
	checkError("udp listen success", err)

	for {
		buf := make([]byte, 256)
		_, err := listen.Read(buf)
		checkError("udp read success", err)
		fmt.Println(string(buf), buf)
	}
}

func main() {
	DNSRelay()
}

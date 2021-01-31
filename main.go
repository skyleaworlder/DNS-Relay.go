package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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

// parseDomainName is a func that draw domain name(string) from struct DNSMsgQst
// e.g. 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00
// 		will be translated into "google.com"
func (qst DNSMsgQst) parseDomainName() (domainName string) {
	domainName = ""
	qname := qst.QNAME
	for i := 0; qname[i] != 0; {
		domainLen := int(qname[i])
		// since length of domain name also occupies an octet
		// for example, "google.com":
		// i++ make j begin at domain name 'g' or 'c', instead of length '0x06' or '0x03'
		i++
		for j := 0; j < domainLen; j++ {
			domainName += string(qname[i+j])
		}
		// it has to be NOTICED that "google.com" will be translated into "google.com."
		domainName += "."
		i += domainLen
	}
	// trim the last '.'
	return strings.Trim(domainName, ".")
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
func parseDNSQst(msg []byte) (dnsMsgQst DNSMsgQst, length uint16) {
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
	length = uint16(i + 5)
	return
}

// parseDNSRequest is a tool function that handle DNS Request MESSAGE
// translate octet-stream to struct DNSMsgHdr/DNSMsgQst defined in RFC-1035
func parseDNSRequest(msg []byte) (dnsMsgHdr DNSMsgHdr, dnsMsgQst DNSMsgQst, length uint16) {
	hdr := msg[0:12]
	dnsMsgHdr = parseDNSHdr(hdr)
	qst := msg[12:]
	dnsMsgQst, qstLen := parseDNSQst(qst)
	length = qstLen + 12
	return
}

// createDNSMsgRR is a function to construct DNSMsgRR
// this Resource Record is Answer
// asrRData is Address or CName, but in my dns relay, it's only Address
func createDNSMsgAsr(asrType uint16, asrClass uint16, asrTTL uint32, asrRDLength uint16, asrRData string) (asr DNSMsgRR) {
	asr.NAME = []byte{0xc0, 0x0c}
	asr.TYPE = asrType
	asr.CLASS = asrClass
	asr.TTL = asrTTL
	asr.RDLENGTH = asrRDLength

	// Dotted Decimal Notation
	address := strings.Split(asrRData, ".")
	for _, octet := range address {
		// in fact, bitSize(parameter) of ParseInt indicates the size of return value
		I, _ := strconv.ParseInt(octet, 10, 9)
		asr.RDATA = append(asr.RDATA, byte(I))
	}
	return
}

// composeHdrQst is a function to compose struct DNSMsgHdr and DNSMsgQst
// this function aims at reusing some code and creating DNS Relay MESSAGE
func composeHdrQst(hdr DNSMsgHdr, qst DNSMsgQst) (relay []byte) {
	// DNS Message Header
	TransactionID := make([]byte, 2)
	Flags := make([]byte, 2)
	Questions := make([]byte, 2)
	AnswerRRs := make([]byte, 2)
	AuthorityRRs := make([]byte, 2)
	AdditionalRRs := make([]byte, 2)
	binary.BigEndian.PutUint16(TransactionID, hdr.ID)
	binary.BigEndian.PutUint16(Flags, hdr.FLAGS)
	binary.BigEndian.PutUint16(Questions, hdr.QDCOUNT)
	binary.BigEndian.PutUint16(AnswerRRs, hdr.ANCOUNT)
	binary.BigEndian.PutUint16(AuthorityRRs, hdr.NSCOUNT)
	binary.BigEndian.PutUint16(AdditionalRRs, hdr.ARCOUNT)

	// DNS Message Questions field
	QstName := qst.QNAME
	QstType := make([]byte, 2)
	QstClass := make([]byte, 2)
	binary.BigEndian.PutUint16(QstType, qst.QTYPE)
	binary.BigEndian.PutUint16(QstClass, qst.QCLASS)

	fields := [][]byte{
		TransactionID, Flags, Questions, AnswerRRs, AuthorityRRs, AdditionalRRs,
		QstName, QstType, QstClass,
	}
	for _, v := range fields {
		relay = append(relay, v...)
	}
	return
}

// composeHdrQstAsr is a function to generate a response to DNS query initiator
// using Header, Question and single Resource Record field to pack an DNS MESSAGE
func composeHdrQstAsr(hdr DNSMsgHdr, qst DNSMsgQst, asr DNSMsgRR) (resp []byte) {
	// compose struct DNSMsgHdr and DNSMsgQst
	resp = composeHdrQst(hdr, qst)

	// DNS Message Answer field
	AsrName := asr.NAME
	AsrType := make([]byte, 2)
	AsrClass := make([]byte, 2)
	AsrTTL := make([]byte, 4)
	AsrDataLength := make([]byte, 2)
	AsrAddress := asr.RDATA
	binary.BigEndian.PutUint16(AsrType, asr.TYPE)
	binary.BigEndian.PutUint16(AsrClass, asr.CLASS)
	binary.BigEndian.PutUint32(AsrTTL, asr.TTL)
	binary.BigEndian.PutUint16(AsrDataLength, asr.RDLENGTH)

	fields := [][]byte{
		AsrName, AsrType, AsrClass, AsrTTL, AsrDataLength, AsrAddress,
	}
	for _, v := range fields {
		resp = append(resp, v...)
	}
	return
}

// composeHdrQstMultiRR is a simple function to comcat hdr, qst and multi-RR
func composeHdrQstMultiRR(hdr DNSMsgHdr, qst DNSMsgQst, rr []byte) (resp []byte) {
	resp = composeHdrQst(hdr, qst)
	resp = append(resp, rr...)
	return
}

func checkError(successInfo string, err error, debug bool) bool {
	if err != nil && debug {
		fmt.Fprintf(os.Stderr, "DNS-Relay> Error occur: %s\n", err.Error())
		os.Exit(1)
	} else if debug {
		fmt.Printf("DNS-Relay> Success: %s\n", successInfo)
		return true
	}
	return false
}

// initDNSHosts is a func to generate hosts map
// this func read "hosts" to initialize hosts and return map to main_func
func initDNSHosts() (hosts map[string]string) {
	file, err := os.Open("hosts")
	checkError("open hosts config success", err, false)
	defer file.Close()

	rd := bufio.NewReader(file)
	hosts = make(map[string]string)
	for {
		line, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		checkError("read hosts config success", err, false)
		// trim \n
		dnsHostsLineArr := strings.Split(strings.Trim(line, "\n"), " ")
		// string.Split get a slice: [ip, ' ', ' ', ' ', ..., domainName]
		// len(slice)-1 to get the last element of slice
		hosts[dnsHostsLineArr[0]] = dnsHostsLineArr[len(dnsHostsLineArr)-1]
	}
	return
}

// findDomainName is a function that draws ip address from hosts map using a given domainName
// if not found, return a string whose length equals 0, and error
// if found, return ip address from map and nil
func getIPAddrByDomainName(hosts map[string]string, domainNameInput string) (ip string, err error) {
	for ip, domainName := range hosts {
		if domainName == domainNameInput {
			return ip, nil
		}
	}
	return "", errors.New("DNS-Relay> Cache Not Found")
}

// communicateWithForwardDNS is a function to send&recv Msg to&from remote DNS
// NOTICE: conn is a parameter that specifies remote DNS ip address
func communicateWithForwardDNS(conn *net.UDPConn, hdr DNSMsgHdr, qst DNSMsgQst) (resp []byte) {
	// use different DNS ID
	resp = make([]byte, 256)
	hdr.ID++
	relay := composeHdrQst(hdr, qst)
	_, err := conn.Write(relay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UDPConn send msg failed: %s\n", err.Error())
	}
	_, err = conn.Read(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "UDPConn recv msg failed: %s\n", err.Error())
	}
	return
}

func coreDNSRelay() {

}

// DNSRelay is the main function
func DNSRelay(hosts map[string]string) {

	// local DNS run over UDP port 53
	port := ":53"
	clientsConn, err := net.ListenPacket("udp", port)
	checkError("udp clients success", err, true)

	// local DNS communicate with remote DNS
	remoteDNSAddr := "192.168.10.1:53"
	udpRemoteDNSAddr, _ := net.ResolveUDPAddr("udp", remoteDNSAddr)
	connToRemote, err := net.DialUDP("udp", nil, udpRemoteDNSAddr)
	checkError("success to create a dial towards remote", err, true)

	for {
		buf := make([]byte, 512)
		_, addr, err := clientsConn.ReadFrom(buf)
		checkError("udp read success", err, true)
		fmt.Println("clients remote addr:", addr, addr.String())
		dnsMsgHdr, dnsMsgQst, _ := parseDNSRequest(buf)
		targetDomainName := dnsMsgQst.parseDomainName()
		targetIP, _ := getIPAddrByDomainName(hosts, targetDomainName)

		fmt.Printf("target IP wuhu: %s, target Domain Name: %s\n", targetIP, targetDomainName)
		if len(targetIP) == 0 {
			fmt.Println("communicate with remote DNS")
			resp := communicateWithForwardDNS(connToRemote, dnsMsgHdr, dnsMsgQst)
			hdr, qst, length := parseDNSRequest(resp)
			hdr.ID--
			resp = composeHdrQstMultiRR(hdr, qst, resp[length:])
			_, err = clientsConn.WriteTo(resp, addr)
			checkError("return udp success", err, true)
			fmt.Println("wuhu!", resp)
		} else if targetIP == "127.0.0.1" || targetIP == "0.0.0.0" {
			// 127.0.0.1 and 0.0.0.0 is 2 types of forbidden ip in DNS hosts
			// RCODE(3) in "0x8183" means name error
			hdr := DNSMsgHdr{
				dnsMsgHdr.ID, 0x8183,
				dnsMsgHdr.QDCOUNT, dnsMsgHdr.ANCOUNT,
				dnsMsgHdr.NSCOUNT, dnsMsgHdr.ARCOUNT,
			}
			resp := composeHdrQst(hdr, dnsMsgQst)
			fmt.Println("resp:", resp)
			clientsConn.WriteTo(resp, addr)
		} else {
			// found in hosts
			fmt.Println("found in hosts:", targetIP, "<=>", targetDomainName)
			hdr := DNSMsgHdr{
				dnsMsgHdr.ID, 0x8180,
				dnsMsgHdr.QDCOUNT, dnsMsgHdr.ANCOUNT,
				dnsMsgHdr.NSCOUNT, dnsMsgHdr.ARCOUNT,
			}
			asr := createDNSMsgAsr(1, 1, 31, 4, targetIP)
			resp := composeHdrQstAsr(hdr, dnsMsgQst, asr)
			fmt.Println("resp:", resp)
			clientsConn.WriteTo(resp, addr)
		}
	}
}

func main() {
	hosts := initDNSHosts()
	DNSRelay(hosts)
}

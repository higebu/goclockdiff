package main

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"text/tabwriter"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/internal/iana"
	"golang.org/x/net/internal/nettest"
	"golang.org/x/net/ipv4"
)

func getAddr(host string, c *icmp.PacketConn, protocol int) (net.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	netaddr := func(ip net.IP) (net.Addr, error) {
		switch c.LocalAddr().(type) {
		case *net.UDPAddr:
			return &net.UDPAddr{IP: ip}, nil
		case *net.IPAddr:
			return &net.IPAddr{IP: ip}, nil
		default:
			return nil, errors.New("neither UDPAddr nor IPAddr")
		}
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return netaddr(ip)
		}
	}
	return nil, errors.New("no A or AAAA record")
}

type Ping struct {
	network, address string
	protocol         int
	mtype            icmp.Type
}

type Timestamp struct {
	ID                int
	Seq               int
	OriginTimestamp   uint32
	ReceiveTimestamp  uint32
	TransmitTimestamp uint32
}

const marshalledTimestampLen = 16

func (t *Timestamp) Len(proto int) int {
	if t == nil {
		return 0
	}
	return marshalledTimestampLen
}

func (t *Timestamp) Marshal(_ int) ([]byte, error) {
	b := make([]byte, marshalledTimestampLen)
	b[0], b[1] = byte(t.ID>>8), byte(t.ID)
	b[2], b[3] = byte(t.Seq>>8), byte(t.Seq)

	unparseInt := func(i uint32) (byte, byte, byte, byte) {
		return byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)
	}
	b[4], b[5], b[6], b[7] = unparseInt(t.OriginTimestamp)
	b[8], b[9], b[10], b[11] = unparseInt(t.ReceiveTimestamp)
	b[12], b[13], b[14], b[15] = unparseInt(t.TransmitTimestamp)
	return b, nil
}

func ParseTimestamp(b []byte) (*Timestamp, error) {
	bodyLen := len(b)
	if bodyLen != marshalledTimestampLen {
		return nil, fmt.Errorf("timestamp body length %d not equal to 16", bodyLen)
	}
	p := &Timestamp{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}

	parseInt := func(start int) uint32 {
		return uint32(b[start])<<24 | uint32(b[start+1])<<16 | uint32(b[start+2])<<8 | uint32(b[start+3])
	}
	p.OriginTimestamp = parseInt(4)
	p.ReceiveTimestamp = parseInt(8)
	p.TransmitTimestamp = parseInt(12)
	return p, nil
}

func doPing(host string, tt *Ping, seq int) error {
	c, err := icmp.ListenPacket(tt.network, tt.address)
	if err != nil {
		return err
	}
	defer c.Close()

	dst, err := getAddr(host, c, tt.protocol)
	if err != nil {
		return err
	}

	now := time.Now()
	today := now.Truncate(24*time.Hour).UnixNano() / 1000000
	transmitTime := uint32(now.UnixNano()/1000000 - today)
	wm := icmp.Message{
		Type: tt.mtype,
		Code: 0,
		Body: &Timestamp{
			ID: os.Getpid() & 0xffff, Seq: 1 << uint(seq),
			OriginTimestamp: transmitTime,
		},
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	if n, err := c.WriteTo(wb, dst); err != nil {
		return err
	} else if n != len(wb) {
		return fmt.Errorf("got %v; want %v", n, len(wb))
	}

	rb := make([]byte, 1500)
	if err := c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	receivedTime := time.Now().UnixNano()/1000000 - today
	rm, err := icmp.ParseMessage(tt.protocol, rb[:n])
	if err != nil {
		return err
	}
	switch rm.Type {
	case ipv4.ICMPTypeTimestampReply:
		b, _ := rm.Body.Marshal(iana.ProtocolICMP)
		ts, err := ParseTimestamp(b)
		if err != nil {
			fmt.Errorf("ParseTimestamp error: %s", err)
		}
		remoteReceiveTime := int64(ts.ReceiveTimestamp)
		rtt := int64(math.Abs(float64(remoteReceiveTime - int64(transmitTime) + receivedTime - int64(ts.TransmitTimestamp))))
		delta := rtt/2 + int64(transmitTime) - remoteReceiveTime
		w := new(tabwriter.Writer)
		w.Init(os.Stdout, 0, 4, 0, '\t', 0)
		fmt.Fprintf(w, "ICMP timestamp:\tOriginate=%d Receive=%d Transmit=%d\n", ts.OriginTimestamp, ts.ReceiveTimestamp, ts.TransmitTimestamp)
		fmt.Fprintf(w, "ICMP timestamp RTT:\ttsrtt=%d\n", rtt)
		fmt.Fprintf(w, "Time difference:\tdelta=%d\n", delta)
		w.Flush()
		return nil
	default:
		return fmt.Errorf("got %+v from %v; want echo reply", rm, peer)
	}
}

func help() {
	fmt.Fprintf(os.Stderr, `NAME
  %s - measure clock difference between hosts
USAGE
  sudo %s <destination>`, os.Args[0], os.Args[0])
	fmt.Println()
	flag.PrintDefaults()
}

func main() {
	flag.Usage = help
	flag.Parse()
	if len(flag.Args()) != 1 {
		help()
	}
	host := flag.Args()[0]
	if _, ok := nettest.SupportsRawIPSocket(); !ok {
		help()
	}
	p := &Ping{"ip4:icmp", "0.0.0.0", iana.ProtocolICMP, ipv4.ICMPTypeTimestamp}
	doPing(host, p, 0)
}

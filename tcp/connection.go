package tcp

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gotcp/tuntap"
	"log"
	"math/rand"
)

const (
	CLOSED = iota
	LISTEN
	SYNRCVD
	ESTAB
)

type TcpState int32

func (t TcpState) String() string {
	switch t {
	case LISTEN:
		return "LISTEN"
	case SYNRCVD:
		return "SYNRCVD"
	case ESTAB:
		return "ESTAB"
	case CLOSED:
		return "CLOSED"
	}
	return "CLOSED"
}

type Connection struct {
	State   TcpState
	SrcIp   string
	DstIp   string
	SrcPort string
	DstPort string
	Nxt     uint32
}

func (c Connection) Send(buf []byte) (n int, err error) {
	return
}

func (c Connection) Rrcv() (buf []byte, err error) {
	return
}

var (
	connections = []Connection{}
)

func Close(conn int) (err error) {
	return
}

func Accept(fd int) (conn int, err error) {
	var connection Connection
	for {
		ip, tcp, err := ReadPacket(fd)
		if err != nil {
			log.Println("err:", err)
			continue
		}
		if connection.State != CLOSED {
			if ip.DstIP.String() != connection.DstIp ||
				ip.SrcIP.String() != connection.SrcIp ||
				tcp.SrcPort.String() != connection.SrcPort ||
				tcp.DstPort.String() != connection.DstPort {
				log.Println("not target ip port")
				continue
			}
		}
		if tcp.SYN {
			connection, err = SendSyn(fd, *ip, *tcp)
			if err != nil {
				fmt.Println("err:", err)
				continue
			}
			continue
		}
		if tcp.ACK && connection.State == SYNRCVD && connection.Nxt == tcp.Ack {
			connection.State = ESTAB
			connections = append(connections, connection)
			conn = len(connections) - 1
			fmt.Println("handshake succeed")
			break
		}
	}
	return
}

func SendSyn(fd int, ip layers.IPv4, tcp layers.TCP) (conn Connection, err error) {
	conn = Connection{
		State:   LISTEN,
		SrcIp:   ip.SrcIP.String(),
		DstIp:   ip.DstIP.String(),
		SrcPort: tcp.SrcPort.String(),
		DstPort: tcp.DstPort.String(),
	}

	ipLay := ip
	ipLay.SrcIP = ip.DstIP
	ipLay.DstIP = ip.SrcIP

	tcpLay := tcp
	tcpLay.SrcPort = tcp.DstPort
	tcpLay.DstPort = tcp.SrcPort
	tcpLay.SYN = true
	tcpLay.ACK = true
	tcpLay.Ack = tcp.Seq + 1
	tcpLay.Seq = uint32(rand.Int())
	tcpLay.Window = 100

	conn.Nxt = tcpLay.Seq + 1

	//  checksum is needed
	tcpLay.SetNetworkLayerForChecksum(&ipLay)
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	},
		&ipLay,
		&tcpLay,
	)
	if err != nil {
		return
	}
	fmt.Println("write:", buffer.Bytes())
	// invalid argument if buffer is not valid ip packet
	_, err = tuntap.Write(fd, buffer.Bytes())

	if err != nil {
		return
	}
	conn.State = SYNRCVD
	return
}

func ReadPacket(fd int) (ip *layers.IPv4, tcp *layers.TCP, err error) {
	buf := make([]byte, 1024)
	n, err := tuntap.Read(fd, buf)
	if err != nil {
		log.Fatal(err)
	}
	pack := gopacket.NewPacket(
		buf[:n],
		layers.LayerTypeIPv4,
		gopacket.Default,
	)
	return UnWrapTcp(pack)
}

func UnWrapTcp(packet gopacket.Packet) (ip *layers.IPv4, tcp *layers.TCP, err error) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		err = errors.New("not valid ipv4 packet")
		return
	}
	ip, _ = ipLayer.(*layers.IPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		err = errors.New("not valid tcp packet")
		return
	}
	tcp, _ = tcpLayer.(*layers.TCP)
	return
}

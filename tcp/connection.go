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

type TcpState int

const (
	CLOSED TcpState = iota
	LISTEN
	SYN_RCVD
	SYN_SENT
	ESTAB
	FIN_WAIT_1
	CLOSE_WAIT
	CLOSING
	FINWAIT_2
	TIME_WAIT
	LAST_ACK
)

func (s TcpState) String() string {
	switch s {
	case CLOSED:
		return "CLOSED"
	case LISTEN:
		return "LISTEN"
	case SYN_RCVD:
		return "SYN_RCVD"
	case SYN_SENT:
		return "SYN_SENT"
	case ESTAB:
		return "ESTAB"
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case CLOSE_WAIT:
		return "CLOSE_WAIT"
	case CLOSING:
		return "CLOSING"
	case FINWAIT_2:
	case TIME_WAIT:
	case LAST_ACK:
		return "LAST_ACK"
	}
	return "UNKNOWN"
}

type Connection struct {
	Nic     int
	State   TcpState
	SrcIp   string
	DstIp   string
	SrcPort string
	DstPort string
	Nxt     uint32
	window  []byte
}

func (c Connection) Window() int {
	return len(c.window)
}

func New(ip *layers.IPv4, tcp *layers.TCP, nic, wind int) Connection {
	conn := Connection{
		Nic:     nic,
		State:   LISTEN,
		SrcIp:   ip.SrcIP.String(),
		DstIp:   ip.DstIP.String(),
		SrcPort: tcp.SrcPort.String(),
		DstPort: tcp.DstPort.String(),
		window:  make([]byte, wind),
	}
	return conn
}

func (c Connection) IsTarget(ip *layers.IPv4, tcp *layers.TCP) bool {
	target := ip.DstIP.String() == c.DstIp &&
		ip.SrcIP.String() == c.SrcIp &&
		tcp.SrcPort.String() == c.SrcPort &&
		tcp.DstPort.String() == c.DstPort
	if !target {
		fmt.Println("not target")
	}
	return target
}

func (c Connection) String() string {
	return fmt.Sprintf("%s:%s -> %s:%s state %s nxt %d nic %d",
		c.SrcIp, c.SrcPort,
		c.DstIp, c.DstPort,
		c.State,
		c.Nxt,
		c.Nic)
}

func Send(conn int, buf []byte) (n int, err error) {
	return
}

func Rcvd(conn int) (buf []byte, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = ConnectionClosedErr{}
		}
	}()
	connection := connections[conn]
	fmt.Println("rcvd:", connection)
	ip, tcp, err := ReadPacket(connection.Nic)
	if err != nil {
		return
	}
	for !connection.IsTarget(ip, tcp) {
		ip, tcp, err = ReadPacket(connection.Nic)
		if err != nil {
			return
		}
		buf = ip.Payload
	}
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
		//fmt.Println(connection)
		ip, tcp, err := ReadPacket(fd)
		if err != nil {
			log.Println("err:", err)
			continue
		}
		if connection.State != CLOSED {
			if !connection.IsTarget(ip, tcp) {
				log.Println("not target ip port")
				continue
			}
		}
		if tcp.SYN {
			connection, err = SendSyn(fd, ip, tcp)
			if err != nil {
				fmt.Println("err:", err)
				continue
			}
			continue
		}
		if tcp.ACK && connection.State == SYN_RCVD && connection.Nxt == tcp.Ack {
			connection.State = ESTAB
			connections = append(connections, connection)
			conn = len(connections) - 1
			fmt.Println("handshake succeed")
			break
		}
	}
	return
}

func SendSyn(fd int, ip *layers.IPv4, tcp *layers.TCP) (conn Connection, err error) {

	conn = New(ip, tcp, fd, 1024)

	ipLay := *ip
	ipLay.SrcIP = ip.DstIP
	ipLay.DstIP = ip.SrcIP

	tcpLay := *tcp
	tcpLay.SrcPort = tcp.DstPort
	tcpLay.DstPort = tcp.SrcPort
	tcpLay.SYN = true
	tcpLay.ACK = true
	tcpLay.Ack = tcp.Seq + 1
	tcpLay.Seq = uint32(rand.Int())
	tcpLay.Window = uint16(conn.Window())

	conn.Nxt = tcpLay.Seq + 1

	//  checksum is needed
	err = tcpLay.SetNetworkLayerForChecksum(&ipLay)
	if err != nil {
		return
	}
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
	conn.State = SYN_RCVD
	return
}

func ReadPacket(fd int) (ip *layers.IPv4, tcp *layers.TCP, err error) {
	buf := make([]byte, 1024)
	fmt.Println("before read")
	n, err := tuntap.Read(fd, buf)
	fmt.Println("after read")
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

type ConnectionClosedErr struct {
}

func (c ConnectionClosedErr) Error() string {
	return "connection closed"
}

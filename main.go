// +build linux

package main

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gotcp/tuntap"
	"log"
)

func main() {
	dev := "mytun"
	//net, err := tuntap.NewTap(dev)
	net, err := tuntap.NewTun(dev)
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetIp(dev, "192.168.1.1/24")
	if err != nil {
		log.Fatal(err)
	}
	err = tuntap.SetUpLink(dev)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("net:", net)
	buf := make([]byte, 1024)
	for {
		n, err := tuntap.Read(net, buf)
		if err != nil {
			log.Fatal(err)
		}
		pack := gopacket.NewPacket(
			buf[:n],
			layers.LayerTypeIPv4,
			gopacket.Default,
		)
		//printPacketInfo(pack)
		conn, err := handle(net, pack)
		if err != nil {
			fmt.Println("err:", err)
		}
		if conn != 0 {
			fmt.Println("connected:", conn)
		}
	}
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

func handle(fd int, packet gopacket.Packet) (conn int, err error) {
	ip, tcp, err := UnWrapTcp(packet)
	if err != nil {
		return
	}
	if tcp.SYN {
		ipLay := *ip
		ipLay.SrcIP = ip.DstIP
		ipLay.DstIP = ip.SrcIP
		//ipLay := layers.IPv4{
		//	SrcIP: ip.DstIP,
		//	DstIP: ip.SrcIP,
		//}
		tcpLay := *tcp
		tcpLay.SrcPort = tcp.DstPort
		tcpLay.DstPort = tcp.SrcPort
		tcpLay.SYN = true
		tcpLay.ACK = true
		tcpLay.Ack = tcp.Seq + 1
		tcpLay.Seq = 123
		//tcpLay := layers.TCP{
		//	SrcPort: tcp.DstPort,
		//	DstPort: tcp.SrcPort,
		//	SYN:     true,
		//	ACK:     true,
		//	Ack:     tcp.Seq + 1,
		//	Seq:     123,
		//}
		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			&ipLay,
			&tcpLay,
		)
		fmt.Println("write:", buffer.Bytes())
		// invalid argument if buffer is not valid ip packet
		_, err = tuntap.Write(fd, buffer.Bytes())
		if err != nil {
			return
		}
	}
	return
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("ethernet %v %v -> %v\n", ethernetPacket.EthernetType, ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
	}
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("ip %v %v -> %v\n", ip.Protocol, ip.SrcIP, ip.DstIP)
	}
	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// TCP layer variables:
		// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
		// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
		fmt.Printf("tcp %v -> %v %v\n", tcp.SrcPort, tcp.DstPort, tcp.Seq)
	}
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Printf("payload:\n%s\n", applicationLayer.Payload())
		// Search for a string inside the payload
		//if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		//	fmt.Println("HTTP found!")
		//}
	}
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

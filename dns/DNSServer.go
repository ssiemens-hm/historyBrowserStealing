package dns

import (
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

var ipstore = make([]string, 0)

func StartDNSServer(channel chan string) {
	fmt.Println("Starting DNS Server...")
	server := &dns.Server{Addr: ":53", Net: "udp"}
	server.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	go checkForKnownIp(channel)
	go server.ListenAndServe()
	fmt.Println("DNS server started!")
	dns.HandleFunc(".", handleRequest)
}

func checkForKnownIp(channel chan string) {
	for {
		ip := <-channel
		fmt.Println("ToCheck got " + ip)

		if !contains(ipstore, ip) {
			fmt.Println("add ip " + ip)
			ipstore = append(ipstore, ip)
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

var (
	cpuprofile  = flag.String("cpuprofile", "", "write cpu profile to file")
	printf      = flag.Bool("print", false, "print replies")
	compress    = flag.Bool("compress", false, "compress replies")
	tsig        = flag.String("tsig", "", "use MD5 hmac tsig: keyname:base64")
	soreuseport = flag.Int("soreuseport", 0, "use SO_REUSE_PORT")
	cpu         = flag.Int("cpu", 0, "number of cpu to use")
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	var (
		v4  bool
		rr  dns.RR
		str string
		a   net.IP
	)
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = *compress
	if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (udp)"
		a = ip.IP
		v4 = a.To4() != nil
	}
	if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		str = "Port: " + strconv.Itoa(ip.Port) + " (tcp)"
		a = ip.IP
		v4 = a.To4() != nil
	}

	remoteIP := strings.Split(w.RemoteAddr().String(), ":")[0]

	ip := net.IPv4(192, 168, 99, 1)
	if contains(ipstore, remoteIP) {

		ips, err := net.LookupIP(r.Question[0].Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
			//os.Exit(1)
		}
		ip = nil
		for _, iprunner := range ips {
			if iprunner.To4() != nil {
				ip = iprunner.To4()
				break
			}
		}
		if ip == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	fmt.Println("Got " + ip.String() + " for " + r.Question[0].Name)

	if v4 {
		rr = &dns.A{
			//			Hdr: dns.RR_Header{Name: dom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},

			//A:   a.To4(),
			A: ip,
		}
	} else {
		rr = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: ip,
		}
	}

	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{str},
	}

	switch r.Question[0].Qtype {
	case dns.TypeTXT:
		m.Answer = append(m.Answer, t)
		m.Extra = append(m.Extra, rr)
	default:
		fallthrough
	case dns.TypeAAAA, dns.TypeA:
		m.Answer = append(m.Answer, rr)
		m.Extra = append(m.Extra, t)
	case dns.TypeAXFR, dns.TypeIXFR:
		c := make(chan *dns.Envelope)
		tr := new(dns.Transfer)
		defer close(c)
		if err := tr.Out(w, r, c); err != nil {
			return
		}
		//soa, _ := dns.NewRR(`whoami.miek.nl. 0 IN SOA linode.atoom.net. miek.miek.nl. 2009032802 21600 7200 604800 3600`)
		//c <- &dns.Envelope{RR: []dns.RR{soa, t, rr, soa}}
		w.Hijack()
		// w.Close() // Client closes connection
		return
	}

	if r.IsTsig() != nil {
		if w.TsigStatus() == nil {
			m.SetTsig(r.Extra[len(r.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			println("Status", w.TsigStatus().Error())
		}
	}
	if *printf {
		fmt.Printf("%v\n", m.String())
	}
	w.WriteMsg(m)
}

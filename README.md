# Browser History Stealing - Proof of concept

Based on https://ieeexplore.ieee.org/document/7527774/references#references

---

To route between the test network and your internet connection it is necessary to enable routing and nat the traffic with ip tables. See https://www.howtoforge.com/nat_iptables

Commands: 
>iptables --table nat --append POSTROUTING --out-interface eth0 -j MASQUERADE

>iptables --append FORWARD --in-interface eth1 -j ACCEPT

After that the iptables service needs to be restarted.

Allow ip forwarding:
>echo 1 > /proc/sys/net/ipv4/ip_forward

To define the interface to answer the DHCP-Requests it's necessary to change "serverif.go" file in the "github.com/krolaw/dhcp4/conn" package 

	
```
// ListenAndServe listens on the UDP network address addr and then calls
 // Serve with handler to handle requests on incoming packets.
 func ListenAndServe(handler Handler) error {
 	l, err := net.ListenPacket("udp4", ":67")
 	if err != nil {
 		return err
 	}
 	defer l.Close()
 	//return Serve(l, handler)
 	intf, _ := net.InterfaceByName("<--your-interface-name-->")
 	return ServeIf(intf.Index, l, handler)
 }
 	
```
See outcomment line and the two new lines below and insert your interface name

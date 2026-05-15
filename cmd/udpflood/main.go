// udpflood injects raw Ethernet/IPv4/UDP frames onto an interface via an
// AF_PACKET socket. Used to stress-test pf on a veth pair: frames sent on
// veth1 arrive on veth0's RX ring (a plain UDP socket would be short-circuited
// by the kernel loopback path and never hit pf).
//
// Usage:
//
//	sudo udpflood -iface veth1 -dst-ip 192.168.99.1 -dst-port 443 -count 100000
//	sudo udpflood -iface veth1 -pps 500000 -duration 5s   # rate-limited
//
// Frames carry a fixed src/dst MAC and a configurable 5-tuple. Payload is
// zero-filled to -size bytes total (Ethernet header included).
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("iface", "", "interface to inject on (required, e.g. veth1)")
	dstIP := flag.String("dst-ip", "192.168.99.1", "destination IPv4")
	srcIP := flag.String("src-ip", "192.168.99.2", "source IPv4")
	dstPort := flag.Int("dst-port", 443, "destination UDP port")
	srcPort := flag.Int("src-port", 12345, "source UDP port")
	size := flag.Int("size", 1000, "total frame size in bytes (>= 42)")
	count := flag.Int("count", 100000, "number of frames to send (0 = until duration)")
	pps := flag.Int("pps", 0, "rate limit in packets/sec (0 = as fast as possible)")
	duration := flag.Duration("duration", 0, "stop after this long (0 = no limit)")
	flag.Parse()

	if *iface == "" {
		fmt.Fprintln(os.Stderr, "usage: udpflood -iface veth1 [-dst-ip ...] [-count N] [-pps N]")
		os.Exit(1)
	}
	if *size < 42 {
		log.Fatalf("size must be >= 42 (eth14 + ip20 + udp8), got %d", *size)
	}

	nic, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatalf("interface %q: %v", *iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  nic.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

	frame := buildFrame(*srcIP, *dstIP, uint16(*srcPort), uint16(*dstPort), *size)

	var (
		sent  uint64
		start = time.Now()
		// for rate limiting
		interval time.Duration
		next     time.Time
	)
	if *pps > 0 {
		interval = time.Second / time.Duration(*pps)
		next = time.Now()
	}

	deadline := time.Time{}
	if *duration > 0 {
		deadline = start.Add(*duration)
	}

	for {
		if *count > 0 && sent >= uint64(*count) {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			break
		}

		if err := unix.Sendto(fd, frame, 0, addr); err != nil {
			// EAGAIN/ENOBUFS under load: just retry
			if err == unix.EAGAIN || err == unix.ENOBUFS {
				continue
			}
			log.Fatalf("sendto: %v", err)
		}
		sent++

		if *pps > 0 {
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}

	elapsed := time.Since(start)
	rate := float64(sent) / elapsed.Seconds()
	fmt.Printf("sent %d frames in %s (%.0f pps, %.2f Mbps)\n",
		sent, elapsed.Round(time.Millisecond), rate,
		rate*float64(*size)*8/1e6)
}

// buildFrame assembles a minimal Ethernet + IPv4 + UDP frame, zero-padded to
// total. IP + UDP checksums are left zero (UDP checksum 0 = "not computed",
// valid per RFC 768; pf does not validate it).
func buildFrame(srcIP, dstIP string, srcPort, dstPort uint16, total int) []byte {
	buf := make([]byte, total)

	// Ethernet: dst MAC broadcast, src MAC arbitrary, type IPv4.
	copy(buf[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(buf[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(buf[12:14], 0x0800)

	ip := buf[14:]
	ipLen := total - 14
	ip[0] = 0x45 // version 4, IHL 5
	ip[1] = 0x00
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen)) // total length
	binary.BigEndian.PutUint16(ip[4:6], 0)             // id
	binary.BigEndian.PutUint16(ip[6:8], 0)             // flags/frag
	ip[8] = 64                                         // TTL
	ip[9] = 17                                         // proto UDP
	// ip[10:12] checksum left 0
	copy(ip[12:16], net.ParseIP(srcIP).To4())
	copy(ip[16:20], net.ParseIP(dstIP).To4())

	udp := ip[20:]
	udpLen := ipLen - 20
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// udp[6:8] checksum 0 = not computed (valid for IPv4/UDP)

	return buf
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

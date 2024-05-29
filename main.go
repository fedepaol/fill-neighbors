// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Aradded struct {
	address string
	when    time.Time
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event arp ebpf/tc_arplistener.c -- -I ebpf/include

func main() {

	var attachTo string
	var fromInterface string

	flag.StringVar(&attachTo, "attach-to", "", "the comma separated list of interfaces to listen for ARP requests from")
	flag.StringVar(&fromInterface, "from-interface", "", "the interface to set the neighbor from")
	flag.Parse()

	interfaces := strings.Split(attachTo, ",")

	// Load pre-compiled programs into the kernel.
	objs := arpObjects{}
	if err := loadArpObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	for _, intf := range interfaces {
		iface, err := net.InterfaceByName(intf)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", intf, err)
		}
		err = attachFilter(iface.Name, objs.arpPrograms.ArpReflect)
		if err != nil {
			log.Fatalf("failed to attach iface %q: %s", intf, err)
		}
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	added := map[string]time.Time{}

	devID, err := net.InterfaceByName(fromInterface)
	if err != nil {
		log.Fatalf("could not get interface ID: %w", err)
	}

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		var event arpEvent
		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		ip := bytesToIP(event.SenderProtoValue)
		mac := bytesToMac(event.SenderHWvalue)
		when := added[ip]
		now := time.Now()
		if now.Sub(when) > time.Minute {
			added[ip] = now
			err := neighborAdd(devID.Index, ip, mac)
			if err != nil {
				log.Printf("neigh add failed: %w", err)
			}
		}
	}

}

func attachFilter(attachTo string, program *ebpf.Program) error {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("failed to replace tc filter: %w", err)
	}
	return nil
}

func neighborAdd(intf int, ip, mac string) error {
	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("failed to parse mac %s: %w", mac, err)
	}
	neigh := &netlink.Neigh{
		LinkIndex:    intf,
		IP:           net.ParseIP(ip),
		State:        netlink.NUD_REACHABLE,
		HardwareAddr: hwAddr,
	}
	err = netlink.NeighAdd(neigh)
	if err != nil {
		return fmt.Errorf("failed to add neigh %v: %w", neigh, err)
	}
	return nil
}

func bytesToIP(b [4]uint8) string {
	bb := make([]byte, 4)
	for i := range b {
		bb[i] = b[i]
	}
	ip := net.IP(bb)
	return ip.To4().String()
}

func bytesToMac(b [6]uint8) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

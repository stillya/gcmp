package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: client <address> <code> <command>")
		os.Exit(1)
	}

	addr := os.Args[1]

	var code [4]uint8
	for i, v := range os.Args[2] {
		code[i] = uint8(v - '0')
	}

	var command, _ = strconv.Atoi(os.Args[3])

	ipaddr, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		fmt.Println("ERROR Can't resolve IP address, ", err)
		os.Exit(1)
	}

	// send the packet
	conn, err := net.DialIP("ip:icmp", nil, ipaddr)
	if err != nil {
		fmt.Println("ERROR Can't dial IP address, ", err)
		os.Exit(1)
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			return
		}
	}()

	icmp := ICMP{
		Type:        EchoRequest,
		Code:        0,
		CheckSum:    0,
		Identifier:  1001,
		SequenceNum: 1001,
	}
	d := &NuclearProtocol{MagicNumber: MagicNumber, Command: uint8(command), Credentials: code}

	icmp.Data = d.Marshal()
	icmp.CheckSum = CSum(icmp.Marshal())
	n, err := conn.Write(icmp.Marshal())

	if err != nil {
		fmt.Println("ERROR Can't write to IP address, ", err)
		os.Exit(1)
	}

	fmt.Printf("INFO Sent %d bytes\n", n)
}

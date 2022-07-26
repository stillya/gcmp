package main

import (
	"fmt"
	log "github.com/go-pkgz/lgr"
	"net"
	"os"
)

var code [4]int

func main() {

	if len(os.Args) < 3 {
		fmt.Println("Usage: server <address> <code>")
		os.Exit(1)
	}

	addr := os.Args[1]

	for i, v := range os.Args[2] {
		code[i] = int(v - '0')
	}
	fmt.Printf("code - %v\n", code)

	log.Setup(log.Debug, log.CallerFile, log.CallerFunc, log.Msec, log.LevelBraces)

	ipAddr, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		log.Printf("ERROR Can't resolve IP address, %v", err)
		return
	}

	conn, err := net.ListenIP("ip:icmp", ipAddr)
	if err != nil {
		log.Printf("ERROR Can't listen on IP address, %v", err)
		return
	}

	log.Printf("INFO Listening on %s", addr)

	defer func() {
		err := conn.Close()
		if err != nil {
			return
		}
	}()

	for {
		b := make([]byte, 5000)

		n, sAddr, err := conn.ReadFromIP(b)

		if err != nil {
			log.Printf("ERROR Can't read from IP address, %v", err)
			break
		}

		log.Printf("INFO Incoming connection from %s", sAddr)
		log.Printf("INFO size of message %d", n)

		go handleMessage(b, sAddr)
	}

}

func handleMessage(b []byte, sAddr *net.IPAddr) {
	icmp := ICMP{}
	icmp.Unmarshal(b)
	nP := NuclearProtocol{}
	nP.Unmarshal(icmp.Data)

	log.Printf("INFO Received ICMP %s", icmp.String())
	if icmp.Type == 0 { // echo reply
		log.Printf("INFO Received ICMP echo reply %s", icmp.String())
		return
	}
	log.Printf("INFO Received Nuclear %s", nP.String())

	if nP.MagicNumber == MAGIC_NUMBER {

	} else {
		log.Printf("INFO Wrong magic number") // response common ping

		resp := ICMP{
			Type:        0,
			Code:        0,
			CheckSum:    0,
			Identifier:  icmp.Identifier,
			SequenceNum: icmp.SequenceNum,
			Data:        icmp.Data,
		}

		resp.CheckSum = CSum(resp.Marshal())

		conn, err := net.Dial("ip:icmp", sAddr.String())
		if err != nil {
			log.Printf("ERROR Can't dial IP address, %v", err)
			return
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Printf("ERROR Can't close connection, %v", err)
				return
			}
		}()

		_, err = conn.Write(resp.Marshal())
		if err != nil {
			log.Printf("ERROR Can't write to IP address, %v", err)
			return
		}

		log.Printf("INFO Sent %s", resp.String())
		return
	}
}

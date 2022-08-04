package main

import (
	"fmt"
	log "github.com/go-pkgz/lgr"
	"net"
	"os"
)

var code [4]uint8

var flag = "flag{I_am_the_nuclear_bomb}"

func _main() {

	if len(os.Args) < 4 {
		fmt.Println("Usage: server <address> <code> <flag>")
		os.Exit(1)
	}

	addr := os.Args[1]

	for i, v := range os.Args[2] {
		code[i] = uint8(v - '0')
	}

	flag = os.Args[3]

	fmt.Printf("code - %v\n", code)
	fmt.Printf("flag - %s\n", flag)

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
		b := make([]byte, EstimateSizeBuffer())

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

func handleMessage(buf []byte, sAddr *net.IPAddr) {
	icmp := ICMP{}
	icmp.Unmarshal(buf)
	nP := NuclearProtocol{}
	nP.Unmarshal(icmp.Data)

	log.Printf("INFO Received ICMP %s", icmp.String())
	if icmp.Type == EchoReply {
		log.Printf("INFO Received ICMP echo reply %s", icmp.String())
		return
	}

	if nP.MagicNumber == MagicNumber {
		log.Printf("INFO Received Nuclear %s", nP.String())
		if nP.Credentials == code {
			log.Printf("INFO Received command %d", nP.Command)

			resp := ICMP{
				Type:        EchoReply,
				Code:        0,
				CheckSum:    0,
				Identifier:  icmp.Identifier,
				SequenceNum: icmp.SequenceNum,
			}

			switch nP.Command {
			case PEW:
				d := &NuclearProtocol{MagicNumber: MagicNumber, Command: nP.Command, Credentials: [4]uint8{0, 0, 0, 0}}
				resp.Data = d.Marshal()
			case NUC:
				d := &NuclearProtocol{MagicNumber: MagicNumber, Command: nP.Command, Credentials: [4]uint8{0, 0, 0, 0}}
				resp.Data = d.Marshal()
				resp.Data = append(resp.Data, []byte(flag)...)
			default:
				log.Printf("ERROR Unknown command %d", nP.Command)
				resp.Data = []byte("what're u doing?")
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
		}
	} else {
		log.Printf("INFO Wrong magic number") // response common ping

		resp := ICMP{
			Type:        EchoReply,
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
	}

	log.Printf("INFO Sent to %s", sAddr)
	return
}

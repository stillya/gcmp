package cmd

import (
	"fmt"
	"gcmp/app/protocol"
	log "github.com/go-pkgz/lgr"
	"net"
)

type ServerCommand struct {
	Address string   `long:"addr" description:"address of interface"`
	Code    [4]uint8 `long:"code" description:"code for authentication purposes"`
	Flag    string   `short:"f" long:"flag" description:"flag for CTF" default:"flag{I_am_the_nuclear_bomb}"`
}

func (s *ServerCommand) Execute(_ []string) error {
	ipAddr, err := net.ResolveIPAddr("ip4", s.Address)
	if err != nil {
		return fmt.Errorf("can't resolve IP address %v", err)
	}

	conn, err := net.ListenIP("ip:icmp", ipAddr)
	if err != nil {
		return fmt.Errorf("can't listen on IP address, %v", err)
	}

	log.Printf("[INFO] listening on %s", s.Address)

	defer func() {
		err := conn.Close()
		if err != nil {
			log.Printf("[ERROR] can't close connection, %v", err)
			return
		}
	}()

	for {
		b := make([]byte, protocol.EstimateSizeBuffer())

		n, sAddr, err := conn.ReadFromIP(b)

		if err != nil {
			log.Printf("[ERROR] can't read from IP address, %v", err)
			break
		}

		log.Printf("[INFO] Incoming connection from %s", sAddr)
		log.Printf("[INFO] size of message %d", n)

		go func() {
			err := s.handleMessage(b, sAddr)
			if err != nil {
				log.Printf("[ERROR] failed to handle message, %v", err)
			}
		}()
	}
	return nil
}

func (s *ServerCommand) handleMessage(buf []byte, sAddr *net.IPAddr) error {
	icmp := protocol.ICMP{}
	icmp.Unmarshal(buf)
	nP := protocol.NuclearProtocol{}
	nP.Unmarshal(icmp.Data)

	if icmp.Type == protocol.EchoReply {
		log.Printf("[INFO] Received ICMP echo reply %s", icmp.String())
	} else {
		log.Printf("[INFO] Received ICMP packet %s", icmp.String())
	}

	if nP.MagicNumber == protocol.MagicNumber {
		log.Printf("[INFO] Received Nuclear %s", nP.String())
		if nP.Credentials == s.Code {
			log.Printf("[INFO] Received command %d", nP.Command)

			resp := protocol.ICMP{
				Type:        protocol.EchoReply,
				Code:        0,
				CheckSum:    0,
				Identifier:  icmp.Identifier,
				SequenceNum: icmp.SequenceNum,
			}

			switch nP.Command {
			case protocol.PEW:
				d := &protocol.NuclearProtocol{MagicNumber: protocol.MagicNumber, Command: nP.Command, Credentials: [4]uint8{0, 0, 0, 0}}
				resp.Data = d.Marshal()
			case protocol.NUC:
				d := &protocol.NuclearProtocol{MagicNumber: protocol.MagicNumber, Command: nP.Command, Credentials: [4]uint8{0, 0, 0, 0}}
				resp.Data = d.Marshal()
				resp.Data = append(resp.Data, []byte(s.Flag)...)
			default:
				log.Printf("[ERROR] Unknown command %d", nP.Command)
				resp.Data = []byte("what're u doing?")
			}

			resp.CheckSum = protocol.CSum(resp.Marshal())

			conn, err := net.Dial("ip:icmp", sAddr.String())
			if err != nil {
				return fmt.Errorf("can't dial ip address, %v", err)
			}
			defer func() {
				err := conn.Close()
				if err != nil {
					log.Printf("[ERROR] Can't close connection, %v", err)
					return
				}
			}()

			_, err = conn.Write(resp.Marshal())
			if err != nil {
				return fmt.Errorf("can't write to ip address, %v", err)
			}
		}
	} else {
		log.Printf("[INFO] Wrong magic number") // response common ping

		resp := protocol.ICMP{
			Type:        protocol.EchoReply,
			Code:        0,
			CheckSum:    0,
			Identifier:  icmp.Identifier,
			SequenceNum: icmp.SequenceNum,
			Data:        icmp.Data,
		}

		resp.CheckSum = protocol.CSum(resp.Marshal())

		conn, err := net.Dial("ip:icmp", sAddr.String())
		if err != nil {
			return fmt.Errorf("can't dial ip address, %v", err)
		}
		defer func() {
			err := conn.Close()
			if err != nil {
				log.Printf("[ERROR] Can't close connection, %v", err)
			}
		}()

		_, err = conn.Write(resp.Marshal())
		if err != nil {
			return fmt.Errorf("can't write to ip address, %v", err)
		}
	}

	log.Printf("[INFO] Sent to %s", sAddr)
	return nil
}

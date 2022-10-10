package cmd

import (
	"fmt"
	"gcmp/app/protocol"
	log "github.com/go-pkgz/lgr"
	"net"
)

type ClientCommand struct {
	Address string   `long:"addr" description:"address of server"`
	Code    [4]uint8 `long:"code" description:"code for authentication purposes"`
	Command int      `long:"cmd" description:"server command"`
}

func (c *ClientCommand) Execute(_ []string) error {
	ipaddr, err := net.ResolveIPAddr("ip4", c.Address)
	if err != nil {
		return fmt.Errorf("can't resolve IP address, %v", err)
	}
	// send the packet
	conn, err := net.DialIP("ip:icmp", nil, ipaddr)
	if err != nil {
		return fmt.Errorf("can't dial IP address, %v", err)
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			log.Printf("[ERROR] can't close connection, %v", err)
			return
		}
	}()

	icmp := protocol.ICMP{
		Type:        protocol.EchoRequest,
		Code:        0,
		CheckSum:    0,
		Identifier:  1001,
		SequenceNum: 1001,
	}
	d := &protocol.NuclearProtocol{MagicNumber: protocol.MagicNumber, Command: uint8(c.Command), Credentials: c.Code}

	icmp.Data = d.Marshal()
	icmp.CheckSum = protocol.CSum(icmp.Marshal())
	n, err := conn.Write(icmp.Marshal())

	if err != nil {
		return fmt.Errorf("can't write to IP address, %v", err)
	}

	log.Printf("[INFO] Sent %d bytes", n)
	return nil
}

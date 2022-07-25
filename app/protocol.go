package main

import (
	"encoding/binary"
	"fmt"
)

const (
	MAGIC_NUMBER       = 0xDEAD
	PING         uint8 = 1
	NUC          uint8 = 5
)

type ICMP struct {
	Type        uint8
	Code        uint8
	CheckSum    uint16
	Identifier  uint16
	SequenceNum uint16
	Data        []byte
}

type NuclearProtocol struct {
	MagicNumber uint32 // 0xDEAD
	Command     uint8
	Credentials [4]uint8
}

func (icmp *ICMP) String() string {
	return fmt.Sprintf("Type: %d, Code: %d, CheckSum: %d, Identifier: %d, SequenceNum: %d, Data: %s", icmp.Type, icmp.Code, icmp.CheckSum, icmp.Identifier, icmp.SequenceNum, icmp.Data)
}

func (icmp *ICMP) Unmarshal(b []byte) {
	icmp.Type = b[0]
	icmp.Code = b[1]
	icmp.CheckSum = binary.BigEndian.Uint16(b[2:4])
	icmp.Identifier = binary.BigEndian.Uint16(b[4:6])
	icmp.SequenceNum = binary.BigEndian.Uint16(b[6:8])
	icmp.Data = b[8:]
}

func (icmp *ICMP) Marshal() []byte {
	b := make([]byte, 8)
	b[0] = icmp.Type
	b[1] = icmp.Code
	binary.BigEndian.PutUint16(b[2:4], icmp.CheckSum)
	binary.BigEndian.PutUint16(b[4:6], icmp.Identifier)
	binary.BigEndian.PutUint16(b[6:8], icmp.SequenceNum)
	b = append(b, icmp.Data...)
	return b
}

func (nP *NuclearProtocol) Marshal() []byte {
	b := make([]byte, 9)
	binary.BigEndian.PutUint32(b[0:4], nP.MagicNumber)
	b[4] = nP.Command
	b[5] = nP.Credentials[0]
	b[6] = nP.Credentials[1]
	b[7] = nP.Credentials[2]
	b[8] = nP.Credentials[3]
	return b
}

func (nP *NuclearProtocol) Unmarshal(b []byte) {
	nP.MagicNumber = binary.BigEndian.Uint32(b[0:4])
	nP.Command = b[4]
	nP.Credentials = [4]uint8{b[5], b[6], b[7], b[8]}
}

func (nP *NuclearProtocol) String() string {
	return fmt.Sprintf("MagicNumber: %d, Command: %d, Credentials: %v", nP.MagicNumber, nP.Command, nP.Credentials)
}

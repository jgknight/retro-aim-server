package oscar

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
)

func ReadAuthChallengeRequest(conn net.Conn) (uint16, error) {

	fmt.Println("Reading snac...")

	var startMarker uint8
	if err := binary.Read(conn, binary.BigEndian, &startMarker); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Printf("start marker: %d\n", startMarker)

	var frameType uint8
	if err := binary.Read(conn, binary.BigEndian, &frameType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Printf("frame type: %d\n", frameType)

	var sequenceNumber uint16
	if err := binary.Read(conn, binary.BigEndian, &sequenceNumber); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("sequence number: %d\n", sequenceNumber)

	var payloadLength uint16
	if err := binary.Read(conn, binary.BigEndian, &payloadLength); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("payload length: %d\n", payloadLength)

	remainder := make([]byte, payloadLength)
	if _, err := conn.Read(remainder); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	snacBuf := bytes.NewBuffer(remainder)

	fmt.Println("Reading Snac header...")

	var foodGroup uint16
	if err := binary.Read(snacBuf, binary.BigEndian, &foodGroup); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("food group: %d\n", foodGroup)
	// 23 = 0x17 = https://wiki.nina.chat/wiki/Protocols/OSCAR#Foodgroups BUCP (0x0017)
	var foodGroupType uint16
	if err := binary.Read(snacBuf, binary.BigEndian, &foodGroupType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("foodGroupType: %d\n", foodGroupType)
	// 6 = 0x0006 = BUCP__CHALLENGE_REQUEST
	var flags uint16
	if err := binary.Read(snacBuf, binary.BigEndian, &flags); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("flags: %d\n", flags)

	var requestID uint32
	if err := binary.Read(snacBuf, binary.BigEndian, &requestID); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("requestID: %d\n", requestID)

	var tag uint16
	if err := binary.Read(snacBuf, binary.BigEndian, &tag); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("tag: %d\n", tag)

	var screenNameLen uint16
	if err := binary.Read(snacBuf, binary.BigEndian, &screenNameLen); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("screenNameLen: %d\n", screenNameLen)

	screenNameBuf := make([]byte, screenNameLen)
	if _, err := snacBuf.Read(screenNameBuf); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("screen name: %s\n", screenNameBuf)

	return sequenceNumber, nil
}

func WriteAuthChallengeResponse(conn net.Conn, sequenceNumber uint16) error {
	fmt.Println("Writing auth challenge response...")

	startMarker := uint8(42)
	if err := binary.Write(conn, binary.BigEndian, startMarker); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	frameType := uint8(2)
	if err := binary.Write(conn, binary.BigEndian, frameType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	seq := uint16(101)
	if err := binary.Write(conn, binary.BigEndian, seq); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	b := make([]byte, 0)
	snacBuf := bytes.NewBuffer(b)

	{
		foodGroup := uint16(0x17)
		if err := binary.Write(snacBuf, binary.BigEndian, foodGroup); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		foodGroupType := uint16(7)
		if err := binary.Write(snacBuf, binary.BigEndian, foodGroupType); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		flags := uint16(0x00)
		if err := binary.Write(snacBuf, binary.BigEndian, flags); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		requestID := uint32(0x00)
		if err := binary.Write(snacBuf, binary.BigEndian, requestID); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		authKey := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
		authKeyLen := uint32(len(authKey))
		if err := binary.Write(snacBuf, binary.BigEndian, authKeyLen); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if _, err := snacBuf.Write(authKey); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}

	payloadLength := uint16(snacBuf.Len())
	if err := binary.Write(conn, binary.BigEndian, payloadLength); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if _, err := conn.Write(snacBuf.Bytes()); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return nil
}

func ReadBUCPLoginRequest(conn net.Conn) (uint16, error) {

	fmt.Println("Reading BUCP login request...")

	var startMarker uint8
	if err := binary.Read(conn, binary.BigEndian, &startMarker); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Printf("start marker: %d\n", startMarker)

	var frameType uint8
	if err := binary.Read(conn, binary.BigEndian, &frameType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Printf("frame type: %d\n", frameType)

	var sequenceNumber uint16
	if err := binary.Read(conn, binary.BigEndian, &sequenceNumber); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("sequence number: %d\n", sequenceNumber)

	var payloadLength uint16
	if err := binary.Read(conn, binary.BigEndian, &payloadLength); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("payload length: %d\n", payloadLength)

	fmt.Println("Reading Snac header...")

	var foodGroup uint16
	if err := binary.Read(conn, binary.BigEndian, &foodGroup); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("food group: %d\n", foodGroup)
	// 23 = 0x17 = https://wiki.nina.chat/wiki/Protocols/OSCAR#Foodgroups BUCP (0x0017)
	var foodGroupType uint16
	if err := binary.Read(conn, binary.BigEndian, &foodGroupType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("foodGroupType: %d\n", foodGroupType)
	// 6 = 0x0006 = BUCP__CHALLENGE_REQUEST
	var flags uint16
	if err := binary.Read(conn, binary.BigEndian, &flags); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("flags: %d\n", flags)

	var requestID uint32
	if err := binary.Read(conn, binary.BigEndian, &requestID); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	fmt.Printf("requestID: %d\n", requestID)

	err := printBUCPTLV(conn)
	if err != nil && err != io.EOF {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return sequenceNumber, nil
}

func WriteBUCPLoginResponse(conn net.Conn, sequenceNumber uint16) error {
	fmt.Println("Writing bucp login response...")

	startMarker := uint8(42)
	if err := binary.Write(conn, binary.BigEndian, startMarker); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	frameType := uint8(2)
	if err := binary.Write(conn, binary.BigEndian, frameType); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	seq := uint16(102)
	if err := binary.Write(conn, binary.BigEndian, seq); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	b := make([]byte, 0)
	snacBuf := bytes.NewBuffer(b)

	{
		foodGroup := uint16(0x17)
		if err := binary.Write(snacBuf, binary.BigEndian, foodGroup); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		foodGroupType := uint16(0x03)
		if err := binary.Write(snacBuf, binary.BigEndian, foodGroupType); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		flags := uint16(0x00)
		if err := binary.Write(snacBuf, binary.BigEndian, flags); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		requestID := uint32(0x00)
		if err := binary.Write(snacBuf, binary.BigEndian, requestID); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if err := writeTLV(snacBuf, 0x01, "myscreenname"); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x08, uint16(0x00)); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x04, ""); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x05, "192.168.64.1:5191"); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x06, []byte("thecookie")); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x11, "mike@localhost"); err != nil {
			return err
		}

		if err := writeTLV(snacBuf, 0x54, "http://localhost"); err != nil {
			return err
		}
	}

	payloadLength := uint16(snacBuf.Len())
	if err := binary.Write(conn, binary.BigEndian, payloadLength); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if _, err := conn.Write(snacBuf.Bytes()); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return nil
}

func writeTLV(w io.Writer, tlvID uint16, val any) error {
	if err := binary.Write(w, binary.BigEndian, tlvID); err != nil {
		return err
	}
	switch val := val.(type) {
	case uint16:
		tlvValLen := uint16(2)
		if err := binary.Write(w, binary.BigEndian, tlvValLen); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, val); err != nil {
			return err
		}
	case uint32:
		tlvValLen := uint16(4)
		if err := binary.Write(w, binary.BigEndian, tlvValLen); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, val); err != nil {
			return err
		}
	case string:
		tlvValLen := uint16(len(val))
		if err := binary.Write(w, binary.BigEndian, tlvValLen); err != nil {
			return err
		}
		_, err := w.Write([]byte(val))
		if err != nil {
			return err
		}
	case []byte:
		tlvValLen := uint16(len(val))
		if err := binary.Write(w, binary.BigEndian, tlvValLen); err != nil {
			return err
		}
		_, err := w.Write(val)
		if err != nil {
			return err
		}
	}
	return nil
}

func printBUCPTLV(r io.Reader) error {

	for {
		var tlvID uint16
		if err := binary.Read(r, binary.BigEndian, &tlvID); err != nil {
			return err
		}

		var tlvValLen uint16
		if err := binary.Read(r, binary.BigEndian, &tlvValLen); err != nil {
			return err
		}

		fmt.Printf("(%d) ", tlvID)
		switch tlvID {
		case 0x01: // screen name
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("screen name: %s", val)
		case 0x03: // client id string
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client id string: %s", val)
		case 0x25: // password md5 hash
			val, err := readBytes(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("password md5 hash: %b\n", val)
		case 0x16: // client id
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client id (len=%d): %d", tlvValLen, val)
		case 0x17: // client major version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client major version (len=%d): %d", tlvValLen, val)
		case 0x18: // client minor version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client minor version (len=%d): %d", tlvValLen, val)
		case 0x19: // client lesser version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client lesser version (len=%d): %d", tlvValLen, val)
		case 0x1A: // client build number
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client build number (len=%d): %d", tlvValLen, val)
		case 0x14: // distribution number
			val, err := readUint32(r)
			if err != nil {
				return err
			}
			fmt.Printf("distribution number (len=%d): %d", tlvValLen, val)
		case 0x0F: // client language (2 symbols)
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client language (2 symbols) (len=%d): %s", tlvValLen, val)
		case 0x0E: // client country (2 symbols)
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client country (2 symbols) (len=%d): %s", tlvValLen, val)
		case 0x4A: // SSI use flag
			val, err := readBytes(r, tlvValLen)
			if err != nil {
				return err
			}
			// buddy list thing?
			fmt.Printf("SSI use flag (len=%d): %d", tlvValLen, val[0])
			return nil
		case 0x004c:
			fmt.Printf("Use old MD5?\n")
		case 0x06:
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("login cookie (len=%d): %s", tlvValLen, val)
		default:
			fmt.Printf("unknown TLV: %d (len=%d)", tlvID, tlvValLen)
			_, err := r.Read(make([]byte, tlvValLen))
			if err != nil {
				return err
			}
		}

		fmt.Println()
	}
}

func PrintTLV(r io.Reader) error {

	for {
		var tlvID uint16
		if err := binary.Read(r, binary.BigEndian, &tlvID); err != nil {
			return err
		}

		var tlvValLen uint16
		if err := binary.Read(r, binary.BigEndian, &tlvValLen); err != nil {
			return err
		}

		fmt.Printf("(%d) ", tlvID)
		switch tlvID {
		case 0x01: // screen name
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("screen name: %s", val)
		case 0x03: // client id string
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client id string: %s", val)
		case 0x25: // password md5 hash
			val, err := readBytes(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("password md5 hash: %b\n", val)
		case 0x16: // client id
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client id (len=%d): %d", tlvValLen, val)
		case 0x17: // client major version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client major version (len=%d): %d", tlvValLen, val)
		case 0x18: // client minor version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client minor version (len=%d): %d", tlvValLen, val)
		case 0x19: // client lesser version
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client lesser version (len=%d): %d", tlvValLen, val)
		case 0x1A: // client build number
			val, err := readUint16(r)
			if err != nil {
				return err
			}
			fmt.Printf("client build number (len=%d): %d", tlvValLen, val)
		case 0x14: // distribution number
			val, err := readUint32(r)
			if err != nil {
				return err
			}
			fmt.Printf("distribution number (len=%d): %d", tlvValLen, val)
		case 0x0F: // client language (2 symbols)
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client language (2 symbols) (len=%d): %s", tlvValLen, val)
		case 0x0E: // client country (2 symbols)
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("client country (2 symbols) (len=%d): %s", tlvValLen, val)
		case 0x4A: // SSI use flag
			val, err := readBytes(r, tlvValLen)
			if err != nil {
				return err
			}
			// buddy list thing?
			fmt.Printf("SSI use flag (len=%d): %d", tlvValLen, val[0])
			return nil
		case 0x004c:
			fmt.Printf("Use old MD5?\n")
		case 0x06:
			val, err := readString(r, tlvValLen)
			if err != nil {
				return err
			}
			fmt.Printf("login cookie (len=%d): %s\n", tlvValLen, val)
			for {
				buf := make([]byte, 1)
				_, err := r.Read(buf)
				if err != nil {
					return nil
				}
				fmt.Println(buf)
			}
		default:
			fmt.Printf("unknown TLV: %d (len=%d)", tlvID, tlvValLen)
			_, err := r.Read(make([]byte, tlvValLen))
			if err != nil {
				return err
			}
		}

		fmt.Println()
	}
}

func readString(r io.Reader, len uint16) (string, error) {
	buf := make([]byte, len)
	if _, err := r.Read(buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readBytes(r io.Reader, len uint16) ([]byte, error) {
	buf := make([]byte, len)
	if _, err := r.Read(buf); err != nil {
		return buf, err
	}
	return buf, nil
}

func readUint16(r io.Reader) (uint16, error) {
	var val uint16
	binary.Read(r, binary.BigEndian, &val)
	return val, nil
}

func readUint32(r io.Reader) (uint32, error) {
	var val uint32
	binary.Read(r, binary.BigEndian, &val)
	return val, nil
}
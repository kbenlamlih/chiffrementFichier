package main

import (
	"bufio"
	"chiffrementFichier/dataAesEncrypter"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func send(c net.Conn, statusCode int, text string) {
	rawSend(c, strconv.Itoa(statusCode)+" "+text)
}

func rawSend(c net.Conn, text string) {
	_, _ = c.Write([]byte(text + "\n"))
}

func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	send(c, 200, "WELCOME")

	encOrDec := dataAesEncrypter.New()

	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))

		if strings.ToUpper(temp) == "STOP" {
			send(c, 290, "GOODBYE")
			break
		}

		fmt.Printf("%s> %s\n", c.RemoteAddr().String(), temp)

		cmd := strings.Fields(temp)

		switch strings.ToUpper(cmd[0]) {
		case "KEY":
			if len(cmd) < 2 {
				send(c, 450, "NO KEY PROVIDED")
				continue
			}
			key := strings.Join(cmd[1:], " ")
			encOrDec.SetStringKey(key)
			fmt.Println("KEY: " + key)
			send(c, 250, "KEY SET")
		case "DATA":
			send(c, 100, "LISTENING")
			rawData, err := bufio.NewReader(c).ReadString('\n')

			var decodeMethod string

			if len(cmd) == 2 {
				switch strings.ToUpper(cmd[1]) {
				case "STR":
					decodeMethod = "str"
				default:
					decodeMethod = "base64"
				}
			}

			fmt.Println(decodeMethod)

			if err != nil {
				send(c, 460, "ERROR RECEIVING DATA")
				fmt.Println(err.Error())
				continue
			}

			rawData = strings.TrimSpace(rawData)

			var decodedData []byte

			switch decodeMethod {
			case "str":
				decodedData = []byte(rawData)
			default:
				decodedData, err = base64.StdEncoding.DecodeString(rawData)
			}

			dataSize := len(decodedData)

			if err != nil {
				send(c, 460, "ERROR RECEIVING DATA")
				fmt.Println(err.Error())
				continue
			}

			encOrDec.SetData(decodedData)

			fmt.Printf("Received data : %d\n", dataSize)
			send(c, 260, strconv.Itoa(dataSize)+" DATA SET")
		case "SHOW":
			msg := fmt.Sprintf("%+v\n", encOrDec)
			fmt.Println(encOrDec)
			send(c, 200, msg)
		case "ENC":
			err := encOrDec.Encrypt()
			if err != nil {
				send(c, 510, "ENC FAILURE")
				fmt.Println(err.Error())
				continue
			}
			encodedData := base64.StdEncoding.EncodeToString(encOrDec.GetEncryptedData())
			send(c, 210, "ENCRYPTED "+encodedData)
		case "DEC":
			err := encOrDec.Decrypt()
			if err != nil {
				send(c, 520, "DEC FAILURE")
				fmt.Println(err.Error())
				continue
			}
			encodedData := base64.StdEncoding.EncodeToString(encOrDec.GetDecryptedData())
			send(c, 220, "DECRYPTED "+encodedData)
		default:
			send(c, 404, "UNKNOWN CMD")
		}
	}
	_ = c.Close()
}

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		return
	}

	PORT := ":" + arguments[1]
	l, err := net.Listen("tcp4", PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	fmt.Println("Listening on localhost" + PORT)

	rand.Seed(time.Now().Unix())

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}

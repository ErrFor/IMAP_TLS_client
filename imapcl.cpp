#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include <thread>
#include <sys/stat.h>

void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void cleanup_ssl(SSL_CTX* ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

int connect_to_server(const std::string& server_ip, int port, SSL_CTX* ctx, bool use_tls) {
    int sockfd;
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return -1;
    }

    if (use_tls) {
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            std::cerr << "SSL connection failed" << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            return -1;
        }

        std::cout << "Connected with SSL encryption" << std::endl;
        SSL_free(ssl);
    } else {
        std::cout << "Connected without encryption" << std::endl;
    }

    return sockfd;
}

bool send_command(int sockfd, const std::string& command, std::string& response) {
    send(sockfd, command.c_str(), command.length(), 0);

    char buffer[4096] = {0};
    int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        response = std::string(buffer);
        std::cout << "Server response: " << response << std::endl;
        return response.find("OK") != std::string::npos;
    } else {
        std::cerr << "No response from server" << std::endl;
        return false;
    }
}

bool receive_response(int sockfd, std::string& response) {
    char buffer[4096] = {0};
    response.clear();

    int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        response = std::string(buffer);
        std::cout << "Server response: " << response << std::endl;
        return true;
    } else {
        std::cerr << "No response from server" << std::endl;
        return false;
    }
}

// Функция для кодирования в Base64
std::string base64_encode(const std::string& input) {
    BIO* bio, *b64;
    BUF_MEM* buffer_ptr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, input.data(), input.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string output(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return output;
}

bool login(int sockfd, const std::string& username, const std::string& password) {
    std::string response;

    // Сначала обрабатываем приветственное сообщение сервера
    if (!receive_response(sockfd, response)) {
        return false;
    }

    // Формируем строку для AUTHENTICATE PLAIN
    std::string auth_data = "\0" + username + "\0" + password;
    std::string encoded_auth_data = base64_encode(auth_data);

    // Отправляем команду AUTHENTICATE PLAIN
    std::string auth_cmd = "a001 AUTHENTICATE PLAIN\r\n";
    send(sockfd, auth_cmd.c_str(), auth_cmd.length(), 0);

    // Ждём ответа сервера
    if (!receive_response(sockfd, response) || response[0] != '+') {
        std::cerr << "Server did not accept AUTHENTICATE PLAIN command" << std::endl;
        return false;
    }

    // Отправляем Base64-закодированную строку
    std::string auth_data_cmd = encoded_auth_data + "\r\n";
    send(sockfd, auth_data_cmd.c_str(), auth_data_cmd.length(), 0);

    // Читаем ответ сервера
    while (receive_response(sockfd, response)) {
        if (response.find("OK") != std::string::npos) {
            std::cout << "Login successful" << std::endl;
            return true;
        } else if (response.find("NO") != std::string::npos || response.find("BAD") != std::string::npos) {
            std::cerr << "Login failed" << std::endl;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    return false;
}

bool select_mailbox(int sockfd, const std::string& mailbox) {
    std::string select_cmd = "a002 SELECT " + mailbox + "\r\n";
    std::string response;
    return send_command(sockfd, select_cmd, response);
}

bool fetch_messages(int sockfd, const std::string& fetch_command, const std::string& out_dir) {
    std::string response;
    if (!send_command(sockfd, fetch_command, response)) {
        std::cerr << "Failed to fetch messages" << std::endl;
        return false;
    }

    // Здесь необходимо добавить код для сохранения сообщений в файлы
    // Используем out_dir для указания каталога для сохранения сообщений

    return true;
}

bool read_credentials(const std::string& filepath, std::string& username, std::string& password) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Failed to open credentials file" << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find("username = ");
        if (pos != std::string::npos) {
            username = line.substr(pos + 11);
        }

        pos = line.find("password = ");
        if (pos != std::string::npos) {
            password = line.substr(pos + 11);
        }
    }

    file.close();

    if (username.empty() || password.empty()) {
        std::cerr << "Credentials file is missing username or password" << std::endl;
        return false;
    }

    return true;
}

bool directory_exists(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false; // Каталог не существует
    } else if (info.st_mode & S_IFDIR) {
        return true; // Это каталог
    } else {
        return false; // Это не каталог
    }
}

int main(int argc, char* argv[]) {
    std::string server_ip;
    int port = 143;
    bool use_tls = false;
    std::string cert_file;
    std::string cert_dir = "/etc/ssl/certs";
    std::string credentials_file;
    std::string mailbox = "INBOX";
    std::string out_dir;
    bool only_headers = false;
    bool only_new = false;

    std::string username, password;

    int opt;
    while ((opt = getopt(argc, argv, "p:TC:c:a:b:o:nh")) != -1) {
        switch (opt) {
            case 'p':
                port = std::stoi(optarg);
                break;
            case 'T':
                use_tls = true;
                port = 993; // Если включено шифрование, используем порт 993 по умолчанию
                break;
            case 'C':
                cert_dir = optarg;
                break;
            case 'c':
                cert_file = optarg;
                break;
            case 'a':
                credentials_file = optarg;
                break;
            case 'b':
                mailbox = optarg;
                break;
            case 'o':
                out_dir = optarg;
                break;
            case 'n':
                only_new = true;
                break;
            case 'h':
                only_headers = true;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n";
                return EXIT_FAILURE;
        }
    }

    // Проверяем, передан ли IP сервера как обязательный аргумент
    if (optind >= argc) {
        std::cerr << "Error: server IP or domain name is required\n";
        return EXIT_FAILURE;
    }
    server_ip = argv[optind];

    initialize_ssl();
    SSL_CTX* ctx = create_context();

    if (credentials_file.empty()) {
        std::cerr << "Error: credentials file is required (-a auth_file)\n";
        return EXIT_FAILURE;
    }

    if (out_dir.empty()) {
        std::cerr << "Error: output directory is required (-o out_dir)\n";
        return EXIT_FAILURE;
    }

    if (!read_credentials(credentials_file, username, password)) {
        return EXIT_FAILURE;
    }

    // Проверка на существование выходного каталога
    if (!directory_exists(out_dir)) {
        std::cerr << "Error: output directory does not exist: " << out_dir << "\n";
        return EXIT_FAILURE;
    }

    if (use_tls && (!cert_file.empty() || !cert_dir.empty())) {
        if (SSL_CTX_load_verify_locations(ctx, cert_file.empty() ? nullptr : cert_file.c_str(), cert_dir.c_str()) <= 0) {
            std::cerr << "Error loading certificates\n";
            cleanup_ssl(ctx);
            return EXIT_FAILURE;
        }
    }

    int sockfd = connect_to_server(server_ip, port, ctx, use_tls);
    if (sockfd < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    if (!login(sockfd, username, password)) {
        std::cerr << "Authentication failed" << std::endl;
        close(sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    if (!select_mailbox(sockfd, mailbox)) {
        std::cerr << "Failed to select mailbox" << std::endl;
        close(sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    std::string fetch_command;
    if (only_headers) {
        fetch_command = "a003 FETCH 1:* (BODY.PEEK[HEADER])\r\n";
    } else if (only_new) {
        fetch_command = "a003 SEARCH UNSEEN\r\n";
    } else {
        fetch_command = "a003 FETCH 1:* (RFC822)\r\n";
    }

    if (!fetch_messages(sockfd, fetch_command, out_dir)) {
        close(sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    close(sockfd);
    cleanup_ssl(ctx);
    return 0;
}

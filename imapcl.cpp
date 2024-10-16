#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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

    // Создаем сокет
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    // Преобразуем IP-адрес сервера
    if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return -1;
    }

    // Подключаемся к серверу
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return -1;
    }

    // Если включено шифрование, устанавливаем SSL-соединение
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
        // Дальнейшие действия с SSL-соединением здесь

        SSL_free(ssl);
    } else {
        std::cout << "Connected without encryption" << std::endl;
        // Дальнейшие действия с нешифрованным соединением здесь
    }

    return sockfd;
}

bool login(int sockfd, const std::string& username, const std::string& password) {
    std::string login_cmd = "a001 LOGIN " + username + " " + password + "\r\n";
    send(sockfd, login_cmd.c_str(), login_cmd.length(), 0);

    char buffer[1024] = {0};
    int bytes_received = recv(sockfd, buffer, sizeof(buffer), 0);
    if (bytes_received > 0) {
        std::string response(buffer);
        std::cout << "Server response: " << response << std::endl;
        if (response.find("OK") != std::string::npos) {
            std::cout << "Login successful" << std::endl;
            return true;
        } else {
            std::cerr << "Login failed" << std::endl;
            return false;
        }
    } else {
        std::cerr << "No response from server during login" << std::endl;
        return false;
    }
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

int main(int argc, char* argv[]) {
    // Параметры по умолчанию
    std::string server_ip = "127.0.0.1";
    int port = 143;
    bool use_tls = false;
    std::string credentials_file = "credentials.txt"; // Имя файла с учётными данными

    // Чтение учётных данных
    std::string username, password;
    if (!read_credentials(credentials_file, username, password)) {
        return EXIT_FAILURE;
    }

    // Инициализация OpenSSL
    initialize_ssl();
    SSL_CTX* ctx = create_context();

    // Подключение к серверу
    int sockfd = connect_to_server(server_ip, port, ctx, use_tls);
    if (sockfd < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    // Авторизация на сервере
    if (!login(sockfd, username, password)) {
        std::cerr << "Authentication failed" << std::endl;
        close(sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    // Закрываем соединение
    close(sockfd);
    cleanup_ssl(ctx);
    return 0;
}

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

int main(int argc, char* argv[]) {
    // Параметры по умолчанию
    std::string server_ip = "127.0.0.1";
    int port = 143;
    bool use_tls = false;

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

    // Закрываем соединение
    close(sockfd);
    cleanup_ssl(ctx);
    return 0;
}

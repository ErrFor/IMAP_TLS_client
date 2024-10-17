// ssl_utils.cpp
#include "ssl_utils.h"
#include <iostream>

void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
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

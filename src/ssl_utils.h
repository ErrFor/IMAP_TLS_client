// ssl_utils.h
#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

/**
 * Initializes the OpenSSL library.
 */
void initialize_ssl();

/**
 * Creates an SSL context.
 * @return SSL_CTX* - Pointer to the newly created SSL context.
 */
SSL_CTX* create_context();

/**
 * Cleans up OpenSSL resources.
 * @param ctx - Pointer to SSL context to be cleaned.
 */
void cleanup_ssl(SSL_CTX* ctx);

#endif // SSL_UTILS_H

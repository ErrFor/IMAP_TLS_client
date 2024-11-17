/**
 * @file ssl_utils.h
 * 
 * @brief Header file with declarations for SSL/TLS utilities.
 * @author Slabik Yaroslav xslabi01
 */

#ifndef SSL_UTILS_H
#define SSL_UTILS_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

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

/**
 * Configures the SSL context with certificates and verification options.
 * @param ctx - SSL context to configure.
 * @param cert_file - Path to the certificate file (optional).
 * @param cert_dir - Path to the certificate directory (optional).
 * @return bool - True if configuration is successful, false otherwise.
 */
bool configure_ssl_context(SSL_CTX* ctx, const std::string& cert_file, const std::string& cert_dir);

#endif // SSL_UTILS_H

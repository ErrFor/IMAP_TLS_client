/**
 * @file ssl_utils.cpp
 * 
 * @brief Implementation of the SSL/TLS utilities.
 * @author Slabik Yaroslav xslabi01
 */

#include "ssl_utils.h"
#include <iostream>
#include <dirent.h>

void initialize_ssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context" << std::endl;
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void cleanup_ssl(SSL_CTX* ctx) {
    SSL_CTX_free(ctx);
    EVP_cleanup();
}

bool configure_ssl_context(SSL_CTX* ctx, const std::string& cert_file, const std::string& cert_dir) {
    // Use default system certificates
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        std::cerr << "Error setting default verify paths\n";
        cleanup_ssl(ctx);
        return false;
    }

    // If user certificates are specified, load them additionally
    if (!cert_file.empty() || !cert_dir.empty()) {
        // Check that the certificate directory is not empty and contains certificates
        if (!cert_dir.empty()) {
            DIR* dir = opendir(cert_dir.c_str());
            if (dir == nullptr) {
                std::cerr << "Cannot open certificate directory: " << cert_dir << "\n";
                cleanup_ssl(ctx);
                return false;
            }
            struct dirent* entry;
            bool has_certificates = false;
            while ((entry = readdir(dir)) != nullptr) {
                std::string filename = entry->d_name;
                if (filename == "." || filename == "..") continue;
                // Check the file extension for .pem or .crt
                if (filename.length() >= 4 &&
                    (filename.substr(filename.length() - 4) == ".pem" ||
                     filename.substr(filename.length() - 4) == ".crt")) {
                    has_certificates = true;
                    break;
                }
            }
            closedir(dir);
            if (!has_certificates) {
                std::cerr << "Certificate directory is empty or contains no valid certificates\n";
                cleanup_ssl(ctx);
                return false;
            }
        }

        // Load certificates from the specified file or directory
        if (SSL_CTX_load_verify_locations(ctx,
                                          cert_file.empty() ? nullptr : cert_file.c_str(),
                                          cert_dir.empty() ? nullptr : cert_dir.c_str()) <= 0) {
            std::cerr << "Error loading certificates\n";
            cleanup_ssl(ctx);
            return false;
        }
    }

    // Set the server certificate validation mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return true;
}
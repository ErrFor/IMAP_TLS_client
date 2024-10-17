// main.cpp
#include <iostream>
#include <string>
#include <vector>
#include <sstream> 
#include <unistd.h>
#include "imap_client.h"
#include "ssl_utils.h"

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
                port = 993; // Default port for TLS
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

    // Check if server IP is provided
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

    // Check if output directory exists
    if (!directory_exists(out_dir)) {
        std::cerr << "Error: output directory does not exist: " << out_dir << "\n";
        return EXIT_FAILURE;
    }

    if (use_tls) {
        if (!cert_file.empty() || !cert_dir.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, cert_file.empty() ? nullptr : cert_file.c_str(),
                                             cert_dir.empty() ? nullptr : cert_dir.c_str()) <= 0) {
                std::cerr << "Error loading certificates\n";
                cleanup_ssl(ctx);
                return EXIT_FAILURE;
            }
        } else {
            // Use default system certificates
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                std::cerr << "Error setting default verify paths\n";
                cleanup_ssl(ctx);
                return EXIT_FAILURE;
            }
        }

        // Set the server certificate validation mode
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    }

    Connection conn = connect_to_server(server_ip, port, ctx, use_tls);

    if (!login(conn, username, password)) {
        std::cerr << "Authentication failed" << std::endl;
        if (conn.use_tls) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
        close(conn.sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    int message_count = 0;
    if (!select_mailbox(conn, mailbox, message_count)) {
        std::cerr << "Failed to select mailbox" << std::endl;
        if (conn.use_tls) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
        close(conn.sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    std::vector<int> message_numbers;

    if (only_new) {
        // Search for unseen messages
        std::string search_command = "a003 SEARCH UNSEEN\r\n";
        std::string search_response;

        if (!send_command(conn, search_command, search_response)) {
            std::cerr << "Failed to search for unseen messages" << std::endl;
            if (conn.use_tls) {
                SSL_shutdown(conn.ssl);
                SSL_free(conn.ssl);
            }
            close(conn.sockfd);
            cleanup_ssl(ctx);
            return EXIT_FAILURE;
        }

        // Parse SEARCH response
        std::istringstream response_stream(search_response);
        std::string line;
        while (std::getline(response_stream, line)) {
            if (line.find("* SEARCH") != std::string::npos) {
                std::istringstream line_stream(line);
                std::string token;
                line_stream >> token; // Skip "*"
                line_stream >> token; // Skip "SEARCH"

                while (line_stream >> token) {
                    int msg_num = std::stoi(token);
                    message_numbers.push_back(msg_num);
                }
            } else if (line.find("OK") != std::string::npos) {
                // End of response
                break;
            }
        }

        if (message_numbers.empty()) {
            std::cout << "Žádné nové zprávy ve schránce " << mailbox << "." << std::endl;
            // Close connection and exit
            if (conn.use_tls) {
                SSL_shutdown(conn.ssl);
                SSL_free(conn.ssl);
            }
            close(conn.sockfd);
            cleanup_ssl(ctx);
            return 0;
        }
    } else {
        // Get all message numbers
        for (int i = 1; i <= message_count; ++i) {
            message_numbers.push_back(i);
        }
    }

    if (!fetch_messages(conn, message_numbers, only_headers, out_dir, mailbox, only_new)) {
        if (conn.use_tls) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
        close(conn.sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    if (conn.use_tls) {
        SSL_shutdown(conn.ssl);
        SSL_free(conn.ssl);
    }
    close(conn.sockfd);
    cleanup_ssl(ctx);
    return 0;
}

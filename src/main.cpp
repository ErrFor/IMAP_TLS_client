/**
 * @file main.cpp
 * 
 * @brief Main program file for the IMAP client application.
 * @author Slabik Yaroslav xslabi01
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream> 
#include <unistd.h>
#include "imap_client.h"
#include "ssl_utils.h"

void usage_print(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir\n";
}

int main(int argc, char* argv[]) {
    std::string server_ip;
    int port = 143;
    bool use_tls = false;
    std::string cert_file;
    std::string cert_dir = "/etc/ssl/certs";
    std::string credentials_file;
    bool cert_file_set = false;
    bool cert_dir_set = false;
    std::string mailbox = "INBOX";
    std::string out_dir;
    bool only_headers = false;
    bool only_new = false;
    SSL_CTX* ctx = nullptr;

    std::string username, password;

    // Parse command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "p:TC:c:a:b:o:nh")) != -1) {
        switch (opt) {
            case 'p':
                try {
                    port = std::stoi(optarg);
                } catch (const std::invalid_argument& e) {
                    std::cerr << "Error: port must contain only numbers.\n";
                    return EXIT_FAILURE;
                }
                break;
            case 'T':
                use_tls = true;
                port = 993; // Default port for TLS
                break;
            case 'C':
                cert_dir = optarg;
                cert_dir_set = true;
                break;
            case 'c':
                cert_file = optarg;
                cert_file_set = true;
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
                usage_print(argv[0]);
                return EXIT_FAILURE;
        }
    }

    // Check if server IP is provided
    if (optind >= argc) {
        std::cerr << "Error: server IP or domain name is required\n";
        usage_print(argv[0]);
        return EXIT_FAILURE;
    }
    server_ip = argv[optind];

    // Checking for additional non-option arguments
    if (++optind < argc) {
        std::cerr << "Error: unexpected argument(s): ";
        while (optind < argc) {
            std::cerr << argv[optind++] << " \n";
        }
        usage_print(argv[0]);
        return EXIT_FAILURE;
    }

    // Check dependencies between options
    if ((cert_file_set || cert_dir_set) && !use_tls) {
        std::cerr << "Error: -C and -c options require -T to be specified.\n";
        usage_print(argv[0]);
        return EXIT_FAILURE;
    }

    if (credentials_file.empty()) {
        std::cerr << "Error: credentials file is required (-a auth_file)\n";
        usage_print(argv[0]);
        return EXIT_FAILURE;
    }

    if (out_dir.empty()) {
        std::cerr << "Error: output directory is required (-o out_dir)\n";
        usage_print(argv[0]);
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
        initialize_ssl();
        ctx = create_context();

        if (!configure_ssl_context(ctx, cert_file, cert_dir)) {
            return EXIT_FAILURE;
        }
    }

    Connection conn = connect_to_server(server_ip, port, ctx, use_tls);

    if (!login(conn, username, password)) {
        if (conn.use_tls) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
        close(conn.sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    // Select mailbox and get list of UIDs
    std::vector<int> server_uids;

    if (!select_mailbox(conn, mailbox, server_uids)) {
        if (conn.use_tls) {
            SSL_shutdown(conn.ssl);
            SSL_free(conn.ssl);
        }
        close(conn.sockfd);
        cleanup_ssl(ctx);
        return EXIT_FAILURE;
    }

    std::vector<int> messages_numbers;

    if (only_new) {
        if (!search_unseen_messages(conn, messages_numbers)) {
            // Clean up and exit
            if (conn.use_tls) {
                SSL_shutdown(conn.ssl);
                SSL_free(conn.ssl);
            }
            close(conn.sockfd);
            if (ctx) cleanup_ssl(ctx);
            return EXIT_FAILURE;
        }

        if (messages_numbers.empty()) {
            std::cout << "Žádné nové zprávy ve schránce " << mailbox << "." << std::endl;
            // Close connection and exit
            if (conn.use_tls) {
                SSL_shutdown(conn.ssl);
                SSL_free(conn.ssl);
            }
            close(conn.sockfd);
            if (ctx) cleanup_ssl(ctx);
            return EXIT_SUCCESS;
        }
    } else {
        // Get all message numbers (UIDs from the server)
        messages_numbers = server_uids;
    }
    
    if (!fetch_messages(conn, server_uids, only_headers, out_dir, mailbox, only_new)) {
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

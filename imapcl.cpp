#include <iostream>
#include <string>
#include <fstream>
#include <regex>
#include <sstream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sys/stat.h>
#include <netdb.h>

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

struct Connection {
    int sockfd;
    SSL* ssl;
    bool use_tls;
};

Connection connect_to_server(const std::string& server, int port, SSL_CTX* ctx, bool use_tls) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct addrinfo hints{}, *res;

    // Clear and set hints structure
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Get address info
    if (getaddrinfo(server.c_str(), nullptr, &hints, &res) != 0) {
        std::cerr << "Invalid address/Domain name not supported" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Set up sockaddr_in structure
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;

    // Create socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        freeaddrinfo(res);
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    SSL* ssl = nullptr;
    if (use_tls) {
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sockfd);

        if (SSL_connect(ssl) <= 0) {
            std::cerr << "SSL connection failed" << std::endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        // Проверяем результат проверки сертификата
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            std::cerr << "Certificate verification failed\n" << server << ".\n";
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            cleanup_ssl(ctx);
            exit(EXIT_FAILURE);
        }
    }

    return {sockfd, ssl, use_tls};
}

bool send_command(Connection& conn, const std::string& command, std::string& response) {
    int bytes_sent;
    if (conn.use_tls) {
        bytes_sent = SSL_write(conn.ssl, command.c_str(), command.length());
    } else {
        bytes_sent = send(conn.sockfd, command.c_str(), command.length(), 0);
    }

    if (bytes_sent <= 0) {
        std::cerr << "Failed to send command" << std::endl;
        return false;
    }

    char buffer[4096] = {0};
    int bytes_received;
    if (conn.use_tls) {
        bytes_received = SSL_read(conn.ssl, buffer, sizeof(buffer) - 1);
    } else {
        bytes_received = recv(conn.sockfd, buffer, sizeof(buffer) - 1, 0);
    }

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        response = std::string(buffer);
        std::cout << "Server response: " << response << std::endl;
        return response.find("OK") != std::string::npos;
    } else {
        std::cerr << "No response from server" << std::endl;
        return false;
    }
}

bool receive_response(Connection& conn, std::string& response) {
    char buffer[4096];
    response.clear();

    while (true) {
        int bytes_received;
        if (conn.use_tls) {
            bytes_received = SSL_read(conn.ssl, buffer, sizeof(buffer) - 1);
        } else {
            bytes_received = recv(conn.sockfd, buffer, sizeof(buffer) - 1, 0);
        }

        if (bytes_received < 0) {
            std::cerr << "Error reading from socket" << std::endl;
            return false;
        } else if (bytes_received == 0) {
            // Connection closed
            break;
        }

        buffer[bytes_received] = '\0';
        response += buffer;

        // Check if response ends with CRLF
        if (response.find("\r\n") != std::string::npos) {
            break;
        }
    }

    std::cout << "Server response: " << response << std::endl;
    return true;
}

// Function to encode in Base64
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

std::string base64_decode(const std::string& encoded_data) {
    // Remove any whitespace or newlines from the encoded data
    std::string clean_input;
    for (char c : encoded_data) {
        if (!isspace(static_cast<unsigned char>(c))) {
            clean_input += c;
        }
    }

    int encoded_length = clean_input.length();
    int decoded_length = (encoded_length / 4) * 3;

    // Allocate buffer for decoded data
    std::vector<unsigned char> decoded_data(decoded_length + 1); // +1 for null terminator

    int output_length = EVP_DecodeBlock(decoded_data.data(), reinterpret_cast<const unsigned char*>(clean_input.c_str()), encoded_length);
    if (output_length < 0) {
        // Error decoding base64
        std::cerr << "Error decoding base64" << std::endl;
        return encoded_data; // Return original if decoding fails
    }

    // Adjust for padding
    if (clean_input[encoded_length - 1] == '=') {
        output_length--;
        if (clean_input[encoded_length - 2] == '=') {
            output_length--;
        }
    }

    decoded_data.resize(output_length);
    return std::string(decoded_data.begin(), decoded_data.end());
}

// Function to decode an encoded word as per RFC 2047
std::string decode_encoded_word(const std::string& encoded_word) {
    std::regex r(R"(=\?([^?]+)\?([bBqQ])\?([^?]+)\?=)");
    std::smatch m;
    if (std::regex_match(encoded_word, m, r)) {
        std::string charset = m[1].str();
        std::string encoding = m[2].str();
        std::string encoded_text = m[3].str();

        // For simplicity, assume charset is UTF-8
        std::string decoded_text;

        if (encoding == "B" || encoding == "b") {
            // Base64 decoding
            decoded_text = base64_decode(encoded_text);
        } else if (encoding == "Q" || encoding == "q") {
            // Quoted-Printable decoding (not implemented here)
            decoded_text = encoded_text; // Placeholder
        } else {
            // Unknown encoding
            decoded_text = encoded_word;
        }

        return decoded_text;
    } else {
        // Not an encoded word
        return encoded_word;
    }
}

bool login(Connection& conn, const std::string& username, const std::string& password) {
    std::string response;

    // Receive server's greeting
    if (!receive_response(conn, response)) {
        return false;
    }

    // Check supported authentication methods
    if (response.find("AUTH=LOGIN") != std::string::npos) {
        // Use LOGIN mechanism
        std::string login_cmd = "a001 LOGIN " + username + " " + password + "\r\n";
        if (!send_command(conn, login_cmd, response)) {
            std::cerr << "Login failed" << std::endl;
            return false;
        }

        std::cout << "Login successful" << std::endl;
        return true;
    } else if (response.find("AUTH=PLAIN") != std::string::npos) {
        // Use PLAIN mechanism
        std::string auth_data = "\0" + username + "\0" + password;
        std::string encoded_auth_data = base64_encode(auth_data);

        std::string auth_cmd = "a001 AUTHENTICATE PLAIN " + encoded_auth_data + "\r\n";
        if (!send_command(conn, auth_cmd, response)) {
            std::cerr << "Authentication failed" << std::endl;
            return false;
        }

        std::cout << "Login successful" << std::endl;
        return true;
    } else {
        std::cerr << "No supported authentication method found" << std::endl;
        return false;
    }
}

bool select_mailbox(Connection& conn, const std::string& mailbox, int& message_count) {
    std::string select_cmd = "a002 SELECT " + mailbox + "\r\n";
    std::string response;
    if (!send_command(conn, select_cmd, response)) {
        return false;
    }

    // Initialize message count
    message_count = 0;

    // Parse response to find the number of messages
    std::istringstream response_stream(response);
    std::string line;
    while (std::getline(response_stream, line)) {
        if (line.find("* ") == 0 && line.find("EXISTS") != std::string::npos) {
            std::istringstream line_stream(line);
            std::string asterisk, num_str, exists;
            line_stream >> asterisk >> num_str >> exists;
            if (exists == "EXISTS") {
                message_count = std::stoi(num_str);
            }
        }
    }

    return true;
}

bool save_message(const std::string& message, const std::string& out_dir, int message_number) {
    // Separate headers and body
    size_t header_end = message.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        header_end = message.find("\n\n");
        if (header_end == std::string::npos) {
            std::cerr << "Failed to find separator between headers and body" << std::endl;
            return false;
        }
    }

    std::string headers = message.substr(0, header_end);
    std::string body = message.substr(header_end + ((message[header_end] == '\r' && message[header_end + 1] == '\n') ? 4 : 2));

    // Search for Content-Transfer-Encoding header in the original headers
    std::string content_transfer_encoding;
    std::istringstream header_stream_cte(headers);
    std::string line;
    while (std::getline(header_stream_cte, line)) {
        // Remove CR if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.find("Content-Transfer-Encoding:") != std::string::npos) {
            content_transfer_encoding = line.substr(line.find(":") + 1);
            // Trim whitespace
            content_transfer_encoding.erase(0, content_transfer_encoding.find_first_not_of(" \t"));
            content_transfer_encoding.erase(content_transfer_encoding.find_last_not_of(" \t\r\n") + 1);
            break;
        }
    }

    // Convert to lower case for comparison
    std::transform(content_transfer_encoding.begin(), content_transfer_encoding.end(), content_transfer_encoding.begin(), ::tolower);

    // Now proceed to filter headers and decode any encoded words
    // List of headers to keep
    const std::vector<std::string> required_headers = {
        "Date", "From", "To", "Subject", "Message-Id", "Message-ID"
    };

    // Decode headers
    std::istringstream header_stream(headers);
    std::ostringstream decoded_headers;
    while (std::getline(header_stream, line)) {
        // Remove CR if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        // Check if the line is one of the required headers
        bool is_required = false;
        for (const auto& header : required_headers) {
            if (line.find(header + ":") == 0) {
                is_required = true;
                break;
            }
        }

        if (!is_required) {
            continue; // Skip this header
        }

        // Decode any encoded words in the line
        std::regex r(R"(=\?[^?]+\?[bBqQ]\?[^?]+\?=)");
        std::smatch m;
        std::string decoded_line;
        std::string::const_iterator search_start(line.cbegin());
        while (std::regex_search(search_start, line.cend(), m, r)) {
            // Append text before the match
            decoded_line += m.prefix().str();

            // Decode the encoded word
            std::string encoded_word = m.str();
            std::string decoded_word = decode_encoded_word(encoded_word);

            decoded_line += decoded_word;

            search_start = m.suffix().first;
        }
        // Append the rest of the line
        decoded_line += std::string(search_start, line.cend());

        decoded_headers << decoded_line << "\r\n";
    }

    headers = decoded_headers.str();

    // Decode body if necessary
    if (content_transfer_encoding == "base64") {
        body = base64_decode(body);
    } else if (content_transfer_encoding == "quoted-printable") {
        // TODO: Implement quoted-printable decoding
    }

    // Reconstruct the message
    std::string full_message = headers + "\r\n" + body;

    // Save to file
    std::string file_path = out_dir + "/message_" + std::to_string(message_number) + ".txt";
    std::ofstream outfile(file_path);

    if (!outfile.is_open()) {
        std::cerr << "Failed to open file: " << file_path << std::endl;
        return false;
    }

    outfile << full_message;
    outfile.close();
    return true;
}

bool read_line(Connection& conn, std::string& line) {
    line.clear();
    char c;
    while (true) {
        int n;
        if (conn.use_tls) {
            n = SSL_read(conn.ssl, &c, 1);
        } else {
            n = recv(conn.sockfd, &c, 1, 0);
        }

        if (n <= 0) {
            return false; // Error or connection closed
        }
        line += c;
        if (line.size() >= 2 && line.substr(line.size() - 2) == "\r\n") {
            break; // End of line
        }
    }
    return true;
}

bool read_literal(Connection& conn, int size, std::string& data) {
    data.clear();
    char buffer[1024];
    int remaining = size;
    while (remaining > 0) {
        int to_read = std::min(remaining, (int)sizeof(buffer));
        int n;
        if (conn.use_tls) {
            n = SSL_read(conn.ssl, buffer, to_read);
        } else {
            n = recv(conn.sockfd, buffer, to_read, 0);
        }

        if (n <= 0) {
            return false; // Error or connection closed
        }
        data.append(buffer, n);
        remaining -= n;
    }
    return true;
}

bool fetch_messages(Connection& conn, const std::vector<int>& message_numbers, bool only_headers, const std::string& out_dir, const std::string& mailbox, bool only_new) {
    int message_count = message_numbers.size();
    int messages_fetched = 0;

    for (int msg_num : message_numbers) {
        std::string fetch_command;
        if (only_headers) {
            fetch_command = "a003 FETCH " + std::to_string(msg_num) + " (BODY.PEEK[HEADER])\r\n";
        } else {
            fetch_command = "a003 FETCH " + std::to_string(msg_num) + " (RFC822)\r\n";
        }

        // Send the FETCH command
        int bytes_sent;
        if (conn.use_tls) {
            bytes_sent = SSL_write(conn.ssl, fetch_command.c_str(), fetch_command.length());
        } else {
            bytes_sent = send(conn.sockfd, fetch_command.c_str(), fetch_command.length(), 0);
        }

        if (bytes_sent <= 0) {
            std::cerr << "Failed to send fetch command" << std::endl;
            return false;
        }

        // Read response
        std::string line;
        while (true) {
            if (!read_line(conn, line)) {
                std::cerr << "Error reading from socket" << std::endl;
                return false;
            }

            // Check for completion of the command
            if (line.find("OK") != std::string::npos && line[0] == 'a') {
                // End of response
                break;
            } else if (line[0] == '*') {
                // Possible data
                if (line.find("FETCH") != std::string::npos) {
                    // Check if line contains a literal indicator {number}
                    size_t pos = line.find("{");
                    if (pos != std::string::npos) {
                        size_t end_pos = line.find("}", pos);
                        if (end_pos != std::string::npos) {
                            std::string num_str = line.substr(pos + 1, end_pos - pos - 1);
                            int literal_size = std::stoi(num_str);

                            // Read the literal data
                            std::string literal_data;
                            if (!read_literal(conn, literal_size, literal_data)) {
                                std::cerr << "Error reading literal data" << std::endl;
                                return false;
                            }

                            // Read the closing parenthesis
                            if (!read_line(conn, line)) {
                                std::cerr << "Error reading from socket" << std::endl;
                                return false;
                            }

                            // Save the message
                            if (!save_message(literal_data, out_dir, msg_num)) {
                                std::cerr << "Failed to save message number: " << msg_num << std::endl;
                                return false;
                            }

                            messages_fetched++;
                        }
                    }
                }
            }
        }
    }

    if (messages_fetched == 0) {
        std::cout << "No messages fetched" << std::endl;
        return false;
    }

    // Output information about the number of downloaded messages
    if (only_headers && only_new) {
        std::cout << "Staženy hlavičky " << messages_fetched << " nových zpráv ze schránky " << mailbox << "." << std::endl;
    } else if (only_headers) {
        std::cout << "Staženy hlavičky " << messages_fetched << " zpráv ze schránky " << mailbox << "." << std::endl;
    } else if (only_new) {
        std::cout << "Staženo " << messages_fetched << " nových zpráv ze schránky " << mailbox << "." << std::endl;
    } else {
        std::cout << "Staženo " << messages_fetched << " zpráv ze schránky " << mailbox << "." << std::endl;
    }

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
        return false; // Directory does not exist
    } else if (info.st_mode & S_IFDIR) {
        return true; // It's a directory
    } else {
        return false; // Not a directory
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
            // Используем системные сертификаты по умолчанию
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                std::cerr << "Error setting default verify paths\n";
                cleanup_ssl(ctx);
                return EXIT_FAILURE;
            }
        }

        // Устанавливаем режим проверки сертификата сервера
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

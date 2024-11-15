// imap_client.cpp
#include "imap_client.h"
#include "ssl_utils.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <regex>
#include <sstream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cctype>

int ssl_read(Connection& conn, void* buf, int num) {
    if (conn.use_tls) {
        return SSL_read(conn.ssl, buf, num);
    } else {
        return recv(conn.sockfd, buf, num, 0);
    }
}

int ssl_write(Connection& conn, const void* buf, int num) {
    if (conn.use_tls) {
        return SSL_write(conn.ssl, buf, num);
    } else {
        return send(conn.sockfd, buf, num, 0);
    }
}

Connection connect_to_server(const std::string& server, int port, SSL_CTX* ctx, bool use_tls) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct addrinfo hints{}, *res;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP

    // Get address info
    if (getaddrinfo(server.c_str(), nullptr, &hints, &res) != 0) {
        std::cerr << "Invalid address/Domain name not supported" << std::endl;
        exit(EXIT_FAILURE);
    }

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
            SSL_free(ssl);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            std::cerr << "Certificate verification failed\n" << server << ".\n";
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            cleanup_ssl(ctx);
            exit(EXIT_FAILURE);
        }

        std::cout << "TSL connection established\n";
    }

    return {sockfd, ssl, use_tls};
}

bool send_command(Connection& conn, const std::string& command, std::string& response) {
    int bytes_sent = ssl_write(conn, command.c_str(), command.length());

    if (bytes_sent <= 0) {
        std::cerr << "Failed to send command" << std::endl;
        return false;
    }

    char buffer[4096] = {0};
    int bytes_received = ssl_read(conn, buffer, sizeof(buffer) - 1);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        response = std::string(buffer);
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
        int bytes_received = ssl_read(conn, buffer, sizeof(buffer) - 1);

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

    return true;
}

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
        std::cerr << "Error decoding base64" << std::endl;
        return encoded_data; // Return original if decoding fails
    }

    if (clean_input[encoded_length - 1] == '=') {
        output_length--;
        if (clean_input[encoded_length - 2] == '=') {
            output_length--;
        }
    }

    decoded_data.resize(output_length);
    return std::string(decoded_data.begin(), decoded_data.end());
}

std::string decode_quoted_printable(const std::string& input) {
    std::string output;
    size_t i = 0;
    while (i < input.length()) {
        if (input[i] == '=') {
            if (i + 2 < input.length() && std::isxdigit(input[i + 1]) && std::isxdigit(input[i + 2])) {
                std::string hex = input.substr(i + 1, 2);
                char ch = static_cast<char>(std::stoi(hex, nullptr, 16));
                output += ch;
                i += 3;
            } else if (i + 1 < input.length() && input[i + 1] == '\n') {
                // Soft line break, skip
                i += 2;
            } else {
                output += input[i];
                i++;
            }
        } else {
            output += input[i];
            i++;
        }
    }
    return output;
}

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
            // Quoted-Printable decoding
            decoded_text = decode_quoted_printable(encoded_text);
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

    // Send LOGIN command
    std::string login_cmd = "a001 LOGIN " + username + " " + password + "\r\n";
    if (!send_command(conn, login_cmd, response)) {
        std::cerr << "Login failed" << std::endl;
        return false;
    }

    // Check if login was successful
    if (response.find("OK") != std::string::npos) {
        return true;
    } else {
        std::cerr << "Login failed: " << response << std::endl;
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
        body = decode_quoted_printable(body);
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
        int n = ssl_read(conn, &c, 1);

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
        int n = ssl_read(conn, buffer, to_read);

        if (n <= 0) {
            return false; // Error or connection closed
        }
        data.append(buffer, n);
        remaining -= n;
    }
    return true;
}

bool fetch_messages(Connection& conn, const std::vector<int>& message_numbers, bool only_headers, const std::string& out_dir, const std::string& mailbox, bool only_new) {
    int messages_fetched = 0;

    for (int msg_num : message_numbers) {
        std::string fetch_command;
        if (only_headers) {
            fetch_command = "a003 FETCH " + std::to_string(msg_num) + " (BODY.PEEK[HEADER])\r\n";
        } else {
            fetch_command = "a003 FETCH " + std::to_string(msg_num) + " (RFC822)\r\n";
        }

        // Send the FETCH command
        int bytes_sent = ssl_write(conn, fetch_command.c_str(), fetch_command.length());

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

/**
 * @file imap_client.h
 * 
 * @brief Header file with declarations for the IMAP client functions.
 * @author Slabik Yaroslav xslabi01
 */

#ifndef IMAP_CLIENT_H
#define IMAP_CLIENT_H

#include <string>
#include <openssl/ssl.h>
#include <vector>

/**
 * Struct representing a connection to the server.
 * Contains socket file descriptor, SSL pointer, and TLS usage flag.
 */
struct Connection {
    int sockfd;
    SSL* ssl;
    bool use_tls;
};

/**
 * Generalized read function that handles both SSL and non-SSL reads.
 * @param conn - Connection object.
 * @param buf - Buffer to read data into.
 * @param num - Number of bytes to read.
 * @return int - Number of bytes read, or <=0 on error.
 */
int ssl_read(Connection& conn, void* buf, int num);

/**
 * Generalized write function that handles both SSL and non-SSL writes.
 * @param conn - Connection object.
 * @param buf - Buffer containing data to write.
 * @param num - Number of bytes to write.
 * @return int - Number of bytes written, or <=0 on error.
 */
int ssl_write(Connection& conn, const void* buf, int num);

/**
 * Establishes a connection to the specified server and port.
 * If TLS is enabled, sets up an SSL connection.
 * @param server - Server address (IP or domain name).
 * @param port - Server port.
 * @param ctx - SSL context for TLS connection.
 * @param use_tls - Boolean flag indicating whether to use TLS.
 * @return Connection - Struct containing connection details.
 */
Connection connect_to_server(const std::string& server, int port, SSL_CTX* ctx, bool use_tls);

/**
 * Sends a command to the IMAP server and receives the response.
 * @param conn - Connection object containing server connection details.
 * @param command - Command to be sent to the server.
 * @param response - String to store the server's response.
 * @return bool - True if command sent successfully and response received.
 */
bool send_command(Connection& conn, const std::string& command, std::string& response);

/**
 * Receives a response from the IMAP server.
 * @param conn - Connection object containing server connection details.
 * @param response - String to store the server's response.
 * @return bool - True if response received successfully.
 */
bool receive_response(Connection& conn, std::string& response);

/**
 * Encodes a string using Base64 encoding.
 * @param input - The string to be encoded.
 * @return std::string - The Base64 encoded string.
 */
std::string base64_encode(const std::string& input);

/**
 * Decodes a Base64 encoded string.
 * @param encoded_data - The Base64 encoded string.
 * @return std::string - The decoded string.
 */
std::string base64_decode(const std::string& encoded_data);

/**
 * Decodes a Quoted-Printable encoded string.
 * @param input - The encoded string.
 * @return std::string - The decoded string.
 */
std::string decode_quoted_printable(const std::string& input);

/**
 * Decodes an encoded word as per RFC 2047.
 * Supports Base64 and Quoted-Printable encodings.
 * @param encoded_word - The encoded word to be decoded.
 * @return std::string - The decoded word.
 */
std::string decode_encoded_word(const std::string& encoded_word);

/**
 * Logs in to the IMAP server using the provided credentials.
 * @param conn - Connection object containing server connection details.
 * @param username - Username for login.
 * @param password - Password for login.
 * @return bool - True if login successful.
 */
bool login(Connection& conn, const std::string& username, const std::string& password);

/**
 * Selects the specified mailbox on the IMAP server.
 * @param conn - Connection object containing server connection details.
 * @param mailbox - Mailbox to select (by default "INBOX").
 * @param message_count - Reference to store the count of messages in the mailbox.
 * @return bool - True if mailbox is successfully selected.
 */
bool select_mailbox(Connection& conn, const std::string& mailbox, int& message_count);

/**
 * Saves the message to the specified output directory.
 * Splits the message into headers and body, keeps only required headers,
 * and optionally decodes the body.
 * @param message - The message to be saved.
 * @param out_dir - The directory to save the message in.
 * @param message_number - The message number for naming the file.
 * @return bool - True if the message is saved successfully.
 */
bool save_message(const std::string& message, const std::string& out_dir, int message_number);

/**
 * Reads a line from the server.
 * Reads character by character until the end of a line (\r\n) is reached.
 * @param conn - Connection object containing server connection details.
 * @param line - String to store the line read from the server.
 * @return bool - True if line read successfully, false if error or connection closed.
 */
bool read_line(Connection& conn, std::string& line);

/**
 * Reads a literal data block of a given size from the server.
 * @param conn - Connection object containing server connection details.
 * @param size - The size of the literal data to be read.
 * @param data - String to store the literal data read from the server.
 * @return bool - True if data read successfully, false if error or connection closed.
 */
bool read_literal(Connection& conn, int size, std::string& data);

/**
 * Fetches messages from the server based on message numbers.
 * Handles both fetching headers only or full message content.
 * @param conn - Connection object containing server connection details.
 * @param message_numbers - Vector containing message numbers to be fetched.
 * @param only_headers - Boolean flag indicating whether to fetch only headers.
 * @param out_dir - Output directory to save the fetched messages.
 * @param mailbox - Mailbox name from which messages are being fetched.
 * @param only_new - Boolean flag indicating if only new messages are being fetched.
 * @return bool - True if messages fetched successfully, false otherwise.
 */
bool fetch_messages(Connection& conn, const std::vector<int>& message_numbers, bool only_headers,
                    const std::string& out_dir, const std::string& mailbox, bool only_new);

/**
 * Reads the credentials (username and password) from a file.
 * @param filepath - Path to the credentials file.
 * @param username - Reference to store the username read from the file.
 * @param password - Reference to store the password read from the file.
 * @return bool - True if credentials read successfully, false otherwise.
 */
bool read_credentials(const std::string& filepath, std::string& username, std::string& password);

/**
 * Checks if a directory exists.
 * @param path - Path to the directory to check.
 * @return bool - True if the directory exists, false otherwise.
 */
bool directory_exists(const std::string& path);

#endif // IMAP_CLIENT_H

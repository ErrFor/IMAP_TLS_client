# README
## Program Description
**imapcl** is an IMAP client implemented in C++. The program allows you to connect to an IMAP server using either an unencrypted connection or a secure SSL/TLS connection. The client supports user authentication, specific mailbox selection 
(e.g. INBOX, Sent, Trash), downloading complete messages or only their headers. The program also provides decoding of Base64 and Quoted-Printable encoded messages and saving messages in RFC 5322 format to a specified directory.
## Usage
```bash
    imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir
```
- `server` is the address of the IMAP server (mandatory),
- `-p port` specifies the port number on the server,
- `-T` enables encryption (imaps),
- `-c` certfile is the certificate file,
- `-c` certaddr is the directory in which to search for certificates,
- `-n` only new messages,
- `-h` only message headers,
- `-auth_file` is a file with user authentication data (mandatory),
- `-b` MAILBOX specifies the mailbox from which messages are to be downloaded,
- `-o out_dir` is the directory where the downloaded messages are to be saved (mandatory)/
### Examples of execution:
Download all messages without using TLS:
```bash
    ./imapcl eva.fit.vutbr.cz -a auth.txt -o messages
    Downloaded 15 messages from the INBOX.
```
Download new messages with TLS and the specified certificate:
```bash
    ./imapcl eva.fit.vutbr.cz -T -c cert.pem -n -a auth.txt -o messages
    TSL connection established. Downloaded 2 new messages from INBOX.
```
Downloaded message headers only:
```bash
    ./imapcl eva.fit.vutbr.cz -h -a auth.txt -o headers
    Downloaded 6 message headers from INBOX.
```
## List of files  
- `src/`
    - `main.cpp` - The main program file that handles command line arguments and coordinates the running of the application.
    - `imap_client.cpp/imap_client.h` - Implementation of functions for IMAP server communication, message processing and decoding.
    - `ssl_utils.cpp/ssl_utils.h` - Implementation of functions for working with SSL/TLS connections and certificates.
- `Makefile` - Build file for compiling the program.
- `manual.pdf` - Program documentation, including description, usage instructions, and test results.
- `README.md` - This file contains a description of the program, examples of how to run it, and a list of uploaded files.
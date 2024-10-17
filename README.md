# README

**Author**: *Slabik Yaroslav*  
**Login**: *xslabi01*  
**Date Created**: *15.11.2024*

## Program Description

**imapcl** is a command-line application that allows reading emails using the **IMAP4rev1** protocol (RFC 3501). The program connects to an IMAP server, downloads messages, and saves them to a specified directory, each message in a separate file. It outputs the number of downloaded messages to the standard output.

### Features

- Connects to an IMAP server using either plain or TLS connection (when the `-T` option is specified).
- Authenticates using the `LOGIN` command with credentials provided from an authentication file.
- Downloads only new messages when the `-n` option is used.
- Downloads only message headers when the `-h` option is used.
- Works with a specified mailbox (using the `-b` option); defaults to `INBOX`.
- Saves messages in the **Internet Message Format** (RFC 5322).

### Limitations

- Only supports authentication using the `LOGIN` command.
- Other authentication methods, such as `AUTH=PLAIN`, are not supported.

## Usage

```bash
    imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o out_dir
```

### Example

```bash
    # Download all messages from INBOX
    ./imapcl eva.fit.vutbr.cz -o maildir -a cred

    # Download only new messages from the "Important" mailbox over TLS
    ./imapcl 10.10.10.1 -p 993 -T -n -b Important -o maildir -a cred

    # Download only headers of all messages from INBOX
    ./imapcl eva.fit.vutbr.cz -o maildir -h -a cred
```

## File List  

- `Makefile` — Build file for compiling the program.
- `src/main.cpp` — Main program file.
- `src/imap_client.h` — Header file with declarations for the IMAP client functions.
- `src/imap_client.cpp` — Implementation of the IMAP client functions.
- `src/ssl_utils.h` — Header file with declarations for SSL/TLS utilities.
- `src/ssl_utils.cpp` — Implementation of the SSL/TLS utilities.
- `manual.pdf` — Program documentation, including description, usage instructions, and test results.
- `README.md` — This file containing the program description.
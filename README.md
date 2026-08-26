# Impostor

SMB1 server for intercepting NTLMv2 Hashes, written in C.

The goal of the project is to implement an SMB1 server as a state machine that correctly accepts and responds to client requests in order to deceive it, leading it to complete an NTLM authentication and thus reveal its own NTLMv2 hash (in a format compatible with `hashcat`/`john`).

> Tool intended for offensive security/red teaming activities and for educational purposes (studying the SMB1/NTLM protocol), to be used exclusively in authorized environments that you own or with explicit consent.

## How it works

The server pretends to be a legitimate SMB1 server and guides the client through a 3-phase state machine:

![State machine schema](docs/schema.png)

| State | Transition |
|-------|-----------|
| 1. `NEGOTIATE` | If an `SMB NEGOTIATE` arrives, following the server's response the state moves to `2. CHALLENGE` |
| 2. `CHALLENGE` | If an `NTLM_NEGOTIATE` arrives, following the server's response the state moves to `3. AUTH` |
| 3. `AUTH` | If an `NTLM_AUTH` arrives, following the server's response the state returns to `1. NEGOTIATE` |

At the implementation level, the outer NetBIOS "envelope" must be taken into account, consisting of 4 bytes, the last 3 of which indicate the length in bytes of the SMB packet.

Each client connection is tracked via a state structure (`client_t` in `server.h`) which, in addition to the state machine's status, maintains:

- a receive buffer (`rx_buf`) with its length, to buffer data read from the socket but not yet fully processed;
- a send buffer (`tx_buf`, with offset `tx_off`) to buffer data to be sent to the client but not yet fully transmitted;
- the `netbios_header_recv` and `netbios_msg_len` fields for tracking the NetBIOS header.

Upon receiving data, it is checked that at least **4 bytes** (NetBIOS header) have been received, the length of the SMB message is determined, the state fields are updated, and finally the message is processed, updating the client's state for the next reception.

The server's main loop is based on `poll()` to handle multiple connections simultaneously in a non-blocking way:

![Main Loop idea for reception](docs/main_loop.png)

When NTLM authentication is completed, the server prints to screen (`[INTERCEPTED] ...`) the username, hostname, domain, and the captured NTLMv2 hash, in the format:

```
username::domain:server_challenge:ntlmv2_response:blob
```

ready to be used with cracking tools such as `hashcat` (mode `-m 5600`) or `john`.

## Project structure

| File | Description |
|------|-------------|
| `server.c` / `server.h` | Entry point, TCP listener setup, client state machine, main loop based on `poll()`, RX/TX buffering, printing of intercepted hashes |
| `smb1_parser.c` / `smb1_parser.h` | Parsing/building of SMB1 packets (header, `NEGOTIATE`, `SESSION_SETUP` commands, flags/flags2, etc.) |
| `spnego_decoder.c` / `spnego_decoder.h` | Decoding of the SPNEGO token (negotiation of the authentication mechanism, extraction of the NTLMSSP blob) contained in SMB messages |
| `asn1_parser.c` / `asn1_parser.h` | Minimal ASN.1 DER parser, used by the SPNEGO decoder to build the ASN.1 structure tree |
| `ntlm_parser.c` / `ntlm_parser.h` | Parsing of NTLMSSP messages (`NEGOTIATE`, `CHALLENGE`, `AUTHENTICATE`) and extraction of username, domain, hostname, and NTLMv2 response |
| `endianness.h` | Utility for handling endianness (little/big endian conversions at runtime) |
| `test.c`, `test2.c` | Test/experimentation files for the parsers |
| `docs/` | Diagrams and supporting material (state machine schema, main loop) |

## Requirements

- A C compiler compatible with the standard used by the project (e.g. `gcc`/`clang`) and a POSIX toolchain (the code uses BSD sockets, `poll()`, `signal()`, etc., so it is intended for Linux/Unix-like environments).


## Compilation

```sh
gcc -o impostor server.c smb1_parser.c spnego_decoder.c asn1_parser.c ntlm_parser.c
```

## Usage

```sh
./impostor [port]
```

- `port` (optional): TCP port on which the server listens. If omitted, the default port defined in `server.h` (`SERVER_PORT`, 9000) is used. It must be a value between 1 and 65535.

On startup, the server prints a banner, version, and configuration information (port, maximum number of clients), then remains listening for connections. When an NTLMv2 hash is captured, the intercepted data (username, hostname, domain, hash) is printed to the screen. The server can be stopped with `Ctrl+C` (`SIGINT`), handled by `intHandler`.

```
 ___                  ___      _    ___        
|_ _|_ __ ___  _ __  / _ \ ___| |_ / _ \ _ __  
 | || '_ ` _ \| '_ \| | | / __| __| | | | '__| 
 | || | | | | | |_) | |_| \__ \ |_| |_| | |    
|___|_| |_| |_| .__/ \___/|___/\__|\___/|_|    
              |_| (v.1.0)             by Lcky  


[*] Version: 1.0
[*] Author: Lcky <luca9vinci at gmail dot com>

[*] Server Info
    Port: 9090
    Max Clients: 50


[*] Listening on port 9090
[*] Waiting for connections...

[INTERCEPTED] Username: test
[INTERCEPTED] Hostname: KALILINUX-2023-02
[INTERCEPTED] Domain  : WORKGROUP
[INTERCEPTED] Hash    : test::WORKGROUP:c4ba87a265de9e09:3482d0efa64fc09a94e44faa83d2a936:01010000000000009A3DE84B6235DD01D36FD06DFF4D64BB000000000200080038004E004900490001001E00570049004E002D00310046005800340055004D005000530034005400420004003400570049004E002D00310046005800340055004D00500053003400540042002E0038004E00490049002E004C004F00430041004C000300140038004E00490049002E004C004F00430041004C000500140038004E00490049002E004C004F00430041004C0008003000300000000000000000000000000000000CAFEB574B56CB6139E261228FBFE3075B4FA9393A3B71031AF3280F4D5A27D00A0010000000000000000000000000000000000009001C0063006900660073002F003100320037002E0030002E0030002E00310000000000
^C
[*] Stopping the server...
```
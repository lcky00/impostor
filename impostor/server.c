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

volatile sig_atomic_t keep_running = 1;

void intHandler(int dummy) {
    keep_running = 0;
}

static void print_ascii_art(){
    printf("%s", ascii_art);
}

static void print_server_info() {
    printf("[*] Version: 1.0\n");
    printf("[*] Author: Lcky <luca9vinci at gmail dot com>\n\n");
    printf("[*] Server Info\n");
    printf("    Port: %d\n", SERVER_PORT);
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
    addr->sin_port = htons(SERVER_PORT);

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

    printf("[*] Listening on port %d\n", SERVER_PORT);
    printf("[*] Waiting for connections...\n");
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
    printf("\n[*] Stopping the server...");

    // Close all connections
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        client_close(&clients[i]);
    }
}

static void start_server(int listen_fd, client_t *clients, struct pollfd *pfds) {

    while(keep_running) {

    }

    // Free the remaining structures
    // ...

}


int main() {
    print_ascii_art();
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
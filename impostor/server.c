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
               SOL_SOCKET,      // Livello dell'opazione che stiamo configurando. Indica che SO_REUSEADDR è un'opzione generica del socket, non specifica di TCP/IP.
               SO_REUSEADDR,    // Abilita SO_REUSEADDR su listen_fd
               &yes,            // puntatore al valore da impostare
               sizeof(yes)
    );
    
    // Bind
    memset(addr, 0, sizeof(*addr));

    addr->sin_family = AF_INET;                // Famiglia di indirizzi. AF_INET è per dire un indirizzo IPv4
    addr->sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY -> tutte le interfacce IPv4 locali.
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
        clients[i].fd = -1;

        clients[i].status = NEGOTIATE;

        clients[i].netbios_header_recv = 0;
        clients[i].netbios_msg_len = 0;

        clients[i].rx_len = 0;
        clients[i].tx_len = 0;
        clients[i].tx_off = 0;
    }
}

static void client_close(client_t *client) {
    if (client->fd != -1) {
        close(client->fd);
    }

    init_client(client);
}

static void start_server(int listen_fd, client_t *clients) {

    while(keep_running) {
        
    }


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
    start_server(listen_fd, clients);

    printf("\n[*] Exiting the server...");
    close(listen_fd);

    return 0;
}
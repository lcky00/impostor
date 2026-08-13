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

volatile sig_atomic_t keep_running = 1;
size_t port = SERVER_PORT;

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

static int client_read_rx(client_t *client) {
    
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
                        
                        printf("[+] New client connected: %s\n", clients[i].client_ip);
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
                //printf("BBB\n");
                continue;
            }

            short events = pfds[i + 1].revents;
            printf("AAAAAA\n");
            
            sleep(1);

            if (events & (POLLERR |
                          POLLHUP |
                          POLLNVAL)) {

                printf("[-] Client disconnected: %s\n", client->client_ip);

                client_close(client);
                continue;
            }

            /**
             * Gestione ricezione
             */
            if (events & POLLIN) {


            }

            /**
             * Gestione invio
             */
            if (client->fd != -1 && (events & POLLOUT)) {


            }

        }
    }

    // Free the remaining structures
    // ...

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
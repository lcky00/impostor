#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 9000
#define MAX_CLIENTS 16

#define RX_SIZE 64 * 1024
#define TX_SIZE 64 * 1024


typedef struct client {
    int fd;

    /*
     * RX:
     *
     * Dati ricevuti dal socket ma non ancora
     * completamente processati.
     */
    unsigned char rx_buf[RX_SIZE];
    size_t rx_len;

    /*
     * TX:
     *
     * Dati che vogliamo mandare al client
     * ma che non sono ancora stati completamente
     * inviati.
     */
    unsigned char tx_buf[TX_SIZE];
    size_t tx_len;
    size_t tx_off;

} client_t;


static void client_init(client_t *client) {
    client->fd = -1;

    client->rx_len = 0;

    client->tx_len = 0;
    client->tx_off = 0;
}


static void client_close(client_t *client) {
    if (client->fd != -1) {
        close(client->fd);
    }

    client_init(client);
}


/*
 * Aggiunge dati al TX buffer.
 */
static int client_queue_tx(client_t *client, const void *data, size_t len) {
    /*
     * Quanto spazio rimane nel buffer?
     */
    size_t available = TX_SIZE - client->tx_len;

    if (len > available) {
        fprintf(stderr, "TX buffer full: dropping connection\n");

        return -1;
    }

    memcpy(client->tx_buf + client->tx_len,
           data,
           len);

    client->tx_len += len;

    return 0;
}


/*
 * Prova a svuotare il TX buffer.
 */
static int client_flush_tx(client_t *client) {
    while (client->tx_off < client->tx_len) {

        ssize_t n = send(
            client->fd,
            client->tx_buf + client->tx_off,
            client->tx_len - client->tx_off,
            MSG_NOSIGNAL
        );

        if (n > 0) {
            /*
             * Abbiamo inviato n byte.
             */
            client->tx_off += (size_t)n;

            continue;
        }

        if (n < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {

            /*
             * Il socket non è attualmente pronto
             * per scrivere.
             *
             * Torniamo al poll().
             */
            return 0;
        }

        if (n < 0 && errno == EINTR) {
            continue;
        }

        /*
         * Errore definitivo.
         */
        return -1;
    }

    /*
     * Tutto il buffer è stato inviato.
     */
    client->tx_len = 0;
    client->tx_off = 0;

    return 0;
}


/*
 * Legge dati dal socket e li mette nel RX buffer.
 */
static int client_read_rx(client_t *client) {
    /*
     * Quanto spazio rimane?
     */
    size_t available = RX_SIZE - client->rx_len;

    if (available == 0) {
        fprintf(stderr, "RX buffer full: dropping connection\n");
        return -1;
    }

    ssize_t n = recv(client->fd, client->rx_buf + client->rx_len, available, 0);

    if (n > 0) {
        client->rx_len += (size_t)n;

        printf("fd=%d received %zd bytes\n", client->fd, n);

        return 0;
    }

    if (n == 0) {
        /*
         * Il client ha chiuso la connessione.
         */
        return -1;
    }

    if (errno == EINTR) {
        return 0;
    }

    if (errno == EAGAIN ||
        errno == EWOULDBLOCK) {

        /*
         * Nessun dato disponibile.
         */
        return 0;
    }

    return -1;
}


/*
 * Per questo esempio il "protocollo" è:
 *
 *     ricevo una riga
 *          ↓
 *     la metto nel TX buffer
 *
 * Un protocollo reale potrebbe invece fare:
 *
 *     RX buffer
 *        ↓
 *     framing
 *        ↓
 *     parser
 *        ↓
 *     risposta
 *        ↓
 *     TX buffer
 */
static int client_process_rx(client_t *client) {
    /*
     * Cerchiamo '\n'.
     */
    size_t message_len = 0;

    for (size_t i = 0; i < client->rx_len; i++) {

        if (client->rx_buf[i] == '\n') {
            message_len = i + 1;
            break;
        }
    }

    /*
     * Non abbiamo ancora ricevuto una riga completa.
     */
    if (message_len == 0) {
        return 0;
    }

    printf("fd=%d complete message: %.*s", client->fd, (int)message_len, client->rx_buf);

    /*
     * Rispondiamo mettendo i dati nel TX buffer.
     *
     * NON facciamo send() qui.
     */
    if (client_queue_tx(client, client->rx_buf, message_len) < 0) {
        return -1;
    }

    /*
     * Abbiamo consumato message_len byte dal RX buffer.
     *
     * Potrebbero esserci altri messaggi già ricevuti.
     */
    size_t remaining = client->rx_len - message_len;
    memmove(client->rx_buf, client->rx_buf + message_len, remaining);
    client->rx_len = remaining;

    return 0;
}


int main(void) {
    int listen_fd;

    struct sockaddr_in addr;

    /*
     * --------------------------------------------------
     * socket()
     * --------------------------------------------------
     */

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    int yes = 1;

    /**
     * Configurazione del socket. 
     */
    setsockopt(listen_fd,       // Socket
               SOL_SOCKET,      // Livello dell'opazione che stiamo configurando. Indica che SO_REUSEADDR è un'opzione generica del socket, non specifica di TCP/IP.
               SO_REUSEADDR,    // Abilita SO_REUSEADDR su listen_fd
               &yes,            // puntatore al valore da impostare
               sizeof(yes)
    );

    /*
     * --------------------------------------------------
     * bind()
     * --------------------------------------------------
     */

    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET; // Famiglia di indirizzi. AF_INET è per dire un indirizzo IPv4
    addr.sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY -> tutte le interfacce IPv4 locali.
    addr.sin_port = htons(SERVER_PORT);

    if (bind(
            listen_fd,
            (struct sockaddr *)&addr,
            sizeof(addr)) < 0) {

        perror("bind");
        close(listen_fd);
        return 1;
    }

    /*
     * --------------------------------------------------
     * listen()
     * --------------------------------------------------
     */

    if (listen(listen_fd, 16) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf("Listening on port %d\n",
           SERVER_PORT);


    /*
     * --------------------------------------------------
     * Client table
     * --------------------------------------------------
     */

    client_t clients[MAX_CLIENTS];

    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_init(&clients[i]);
    }


    /*
     * --------------------------------------------------
     * poll()
     * --------------------------------------------------
     */

    struct pollfd pfds[MAX_CLIENTS + 1];

    while (1) {

        /*
         * Lo slot 0 è il listening socket.
         */
        pfds[0].fd = listen_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;


        /*
         * Costruiamo la lista dei client.
         */
        for (int i = 0; i < MAX_CLIENTS; i++) {

            pfds[i + 1].fd = clients[i].fd;
            pfds[i + 1].events = 0;
            pfds[i + 1].revents = 0;

            if (clients[i].fd == -1) {
                continue;
            }

            /*
             * Ci interessa leggere.
             */
            pfds[i + 1].events |= POLLIN;

            /*
             * Ci interessa scrivere SOLO se
             * abbiamo dati nel TX buffer.
             */
            if (clients[i].tx_off < clients[i].tx_len) {
                pfds[i + 1].events |= POLLOUT;
            }
        }


        /*
         * Aspettiamo eventi.
         */
        int ret = poll(
            pfds,
            MAX_CLIENTS + 1,
            -1
        );

        if (ret < 0) {

            if (errno == EINTR) {
                continue;
            }

            perror("poll");
            break;
        }
        
        /*
         * --------------------------------------------------
         * Nuove connessioni
         * --------------------------------------------------
         */
        if (pfds[0].revents & POLLIN) {

            int client_fd = accept(
                listen_fd,
                NULL,
                NULL
            );

            if (client_fd < 0) {

                perror("accept");

            } else {

                int inserted = 0;

                for (int i = 0; i < MAX_CLIENTS; i++) {

                    if (clients[i].fd == -1) {

                        clients[i].fd = client_fd;

                        printf("Client connected: fd=%d\n", client_fd);

                        inserted = 1;
                        break;
                    }
                }

                if (!inserted) {
                    printf("Too many clients\n");
                    close(client_fd);
                }
            }
        }


        /*
         * --------------------------------------------------
         * Gestione client
         * --------------------------------------------------
         */

        for (int i = 0; i < MAX_CLIENTS; i++) {
            client_t *client = &clients[i];

            if (client->fd == -1) {
                continue;
            }

            short events =
                pfds[i + 1].revents;


            /*
             * Errori / disconnect.
             */
            if (events & (POLLERR |
                          POLLHUP |
                          POLLNVAL)) {

                printf("Client disconnected: fd=%d\n", client->fd);

                client_close(client);
                continue;
            }


            /*
             * --------------------------------------------------
             * RX
             * --------------------------------------------------
             */

            if (events & POLLIN) {

                if (client_read_rx(client) < 0) {

                    printf("Closing client fd=%d\n", client->fd);

                    client_close(client);
                    continue;
                }

                /*
                 * Proviamo a processare ciò che abbiamo
                 * ricevuto.
                 *
                 * Potrebbero esserci più messaggi.
                 */
                while (client->rx_len > 0) {

                    size_t before =
                        client->rx_len;

                    if (client_process_rx(client) < 0) {

                        client_close(client);
                        break;
                    }

                    /*
                     * Non c'è un messaggio completo.
                     */
                    if (client->rx_len == before) {
                        break;
                    }
                }
            }


            /*
             * --------------------------------------------------
             * TX
             * --------------------------------------------------
             */

            if (client->fd != -1 && (events & POLLOUT)) {

                if (client_flush_tx(client) < 0) {

                    printf(
                        "TX error: fd=%d\n",
                        client->fd
                    );

                    client_close(client);
                    continue;
                }
            }
        }
    }

    close(listen_fd);

    return 0;
}
#include <stdlib.h>

#define RX_SIZE 64 * 1024
#define TX_SIZE 64 * 1024

typedef enum {
    NEGOTIATE,
    CHALLENGE,
    AUTH
} client_status_t;

typedef struct client {
    int fd;
    
    client_status_t status;

    int netbios_header_recv;
    size_t netbios_msg_len;

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

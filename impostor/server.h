#include <stdlib.h>

#define SERVER_PORT 9000

#define RX_SIZE 64 * 1024
#define TX_SIZE 64 * 1024

#define BACKLOG 16
#define MAX_CLIENTS 50

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
     * Data received from the socket but not yet fully processed.
     */
    unsigned char rx_buf[RX_SIZE];
    size_t rx_len;

    /*
     * TX:
     *
     * Data intended for the client but not yet fully sent.
     */
    unsigned char tx_buf[TX_SIZE];
    size_t tx_len;
    size_t tx_off;

} client_t;


const char *ascii_art =
" ___                  ___      _    ___        \n"
"|_ _|_ __ ___  _ __  / _ \\ ___| |_ / _ \\ _ __  \n"
" | || '_ ` _ \\| '_ \\| | | / __| __| | | | '__| \n"
" | || | | | | | |_) | |_| \\__ \\ |_| |_| | |    \n"
"|___|_| |_| |_| .__/ \\___/|___/\\__|\\___/|_|    \n"
"              |_| (v.1.0)             by Lcky  \n\n\n";

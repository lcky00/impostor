/**
 * Parser for NTLM Authentication Protocol
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/907f519d-6217-45b1-b421-dca10fc8af0d
 * 
 * Luca Vinci <luca9vinci at gmail dot com>
 * 
 * Parser non ero-copy, crea copia del buffer nella struttura di output.
 * Andarà liberata memoria dal chiamante. Non intacca buffer.
 * 
 * All numeric fields in output are host-endian.
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Errori parsing */
#define NTLM_PARSER_OK                                  0x00000000
#define NTLM_PARSER_ERROR_INVALID_ARGS                  0x80000001
#define NTLM_PARSER_ERROR_INVALID_SIGNATURE             0x80000002
#define NTLM_PARSER_ERROR_INVALID_MSG_TYPE              0x80000003
#define NTLM_PARSER_ERROR_BUFF_OVERFLOW                 0x80000004
#define NTLM_PARSER_ERROR_BUFF_TOO_BIG                  0x80000005
#define NTLM_PARSER_ERROR_MALFORMED_MSG                 0x80000006
#define NTLM_PARSER_ERROR_FREE_INVALID_TYPE_MSG         0x80000007
#define NTLM_PARSER_ERROR_INVALID_CTX_BUFFER            0x80000008
#define NTLM_PARSER_ERROR_READ_OVERFLOW                 0x80000009
#define NTLM_PARSER_ERROR_MAX_LEN_BLOB_EXEEDED          0x8000000a
#define NTLM_PARSER_ERROR_ALLOC_BLOB                    0x8000000b
#define NTLM_PARSER_ERROR_OFFSET_OVERFLOW               0x8000000c
#define NTLM_PARSER_ERROR_INVALID_NTLM_RESPONSE_SIZE    0x8000000d
#define NTLM_PARSER_ERROR_INVALID_BLOB                  0x8000000e
#define NTLM_PARSER_ERROR_PARSE_NTLM_V2_CLIENT_CHALLENGE_LEN 0x8000000f
#define NTLM_PARSER_ERROR_INVALID_AV_ID                 0x80000010
#define NTLM_PARSER_ERROR_INVALID_AV_LEN                0x80000011
#define NTLM_PARSER_ERROR_ALLOC_AV_PAIR                 0x80000012

typedef int32_t ntlm_parser_error;

/* Costanti utili (dimensioni, limiti)*/
#define NTLM_MAX_MSG_DIM                        (64 * 1024)     // 64 KB

#define NTLM_HEADER_SIGNATURE_SIZE              8               // 8 Bytes
#define NTLM_HEADER_MIC_SIZE                    16              // 16 Bytes
#define NTLM_BLOB_MAX_LEN                       (4 * 1024)      // 4 KB
#define NTLM_HEADER_FIELDS_SIZE                 8
#define NTLM_HEADER_VERSION_SIZE                8
#define NTLM_HEADER_SERVER_CHALLENGE_SIZE       8


#define NTLM_V2_RESPONSE_SIZE                   16              // 16 Bytes
#define NTLM_RESPONSE_SIZE                      24              // 24 Bytes
#define NTLM_V2_RESP_MIN_LEN                    44              // Fixed Header size

#define LM_V2_RESPONSE_SIZE                     16              // 16 Bytes
#define LM_RESPONSE_SIZE                        24              // 24 Bytes

#define AV_PAIR_HEADER_SIZE                     4

/* Tipi messaggi NTLM */
#define NEGOTIATE_MESSAGE    0x00000001
#define CHALLENGE_MESSAGE    0x00000002
#define AUTHENTICATE_MESSAGE 0x00000003

typedef uint32_t ntlm_msg_type_t;

/* Tipi per LM Response per payload */
#define LM_RESPONSE_V1 0x01
#define LM_RESPONSE_V2 0x02

typedef uint8_t lm_response_type_t;

/* Tipi per NTLM Response per payload */
#define NTLM_RESPONSE_V1 0x01
#define NTLM_RESPONSE_V2 0x02

typedef uint8_t ntlm_response_type_t;

/* Firma del protcollo */
static const uint8_t ntlm_protocol_sign[NTLM_HEADER_SIGNATURE_SIZE] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};

typedef uint32_t ntlm_negotiate_flags_t;

/******************************************/
//               NegFlags
/******************************************/
#define NTLMSSP_NEGOTIATE_56                            0x80000000

// If the NTLMSSP_NEGOTIATE_KEY_EXCH flag is set 
// in NegotiateFlags, indicating that an 
// EncryptedRandomSessionKey is supplied, 
#define NTLMSSP_NEGOTIATE_KEY_EXCH                      0x40000000
#define NTLMSSP_NEGOTIATE_128                           0x20000000
#define NTLMSSP_NEGOTIATE_R1                            0x10000000
#define NTLMSSP_NEGOTIATE_R2                            0x08000000
#define NTLMSSP_NEGOTIATE_R3                            0x04000000

// The data corresponding to this flag is provided 
// in the Version field of the NEGOTIATE_MESSAGE
#define NTLMSSP_NEGOTIATE_VERSION                       0x02000000  
#define NTLMSSP_NEGOTIATE_R4                            0x01000000  

// Indicates that the TargetInfo fields in the 
// CHALLENGE_MESSAGE are populated.
#define NTLMSSP_NEGOTIATE_TARGET_INFO                   0x00800000  
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY              0x00400000
#define NTLMSSP_NEGOTIATE_R5                            0x00200000
#define NTLMSSP_NEGOTIATE_IDENTIFY                      0x00100000
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY      0x00080000
#define NTLMSSP_NEGOTIATE_R6                            0x00040000

// TargetName MUST be a server name. The data 
// corresponding to this flag is provided by the server 
// in the TargetName field of the CHALLENGE_MESSAGE 
#define NTLMSSP_TARGET_TYPE_SERVER                      0x00020000 

// The data corresponding to this flag is provided by the
// server in the TargetName field of the CHALLENGE_MESSAGE
#define NTLMSSP_TARGET_TYPE_DOMAIN                      0x00010000
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN                   0x00008000
#define NTLMSSP_NEGOTIATE_R7                            0x00004000

// This flag indicates whether the Workstation field 
// is present. If this flag is not set, the Workstation
// field MUST be ignored.
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED      0x00002000

// If set, the domain name is provided
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED           0x00001000
#define NTLMSSP_NEGOTIATE_J                             0x00000800
#define NTLMSSP_NEGOTIATE_R8                            0x00000400

// If set, requests usage of the NTLM v1 session 
// security protocol
#define NTLMSSP_NEGOTIATE_NTLM                          0x00000200
#define NTLMSSP_NEGOTIATE_R9                            0x00000100
#define NTLMSSP_NEGOTIATE_LM_KEY                        0x00000080
#define NTLMSSP_NEGOTIATE_DATAGRAM                      0x00000040
#define NTLMSSP_NEGOTIATE_SEAL                          0x00000020
#define NTLMSSP_NEGOTIATE_SIGN                          0x00000010
#define NTLMSSP_NEGOTIATE_R10                           0x00000008

// If set, a TargetName field of the CHALLENGE_MESSAGE
// MUST be supplied.
#define NTLMSSP_REQUEST_TARGET                          0x00000004
#define NTLM_NEGOTIATE_OEM                              0x00000002
#define NTLMSSP_NEGOTIATE_UNICODE                       0x00000001

/******************************************/
//               AV_PAIR ID
/******************************************/

#define MSV_AV_EOL                  0x0000
#define MSV_AV_NB_COMPUTER_NAME     0x0001
#define MSV_AV_NB_DOMAIN_NAME       0x0002
#define MSV_AV_DNS_COMPUTER_NAME    0x0003
#define MSV_AV_DNS_DOMAIN_NAME      0x0004
#define MSV_AV_DNS_TREE_NAME        0x0005
#define MSV_AV_FLAGS                0x0006
#define MSV_AV_TIMESTAMP            0x0007
#define MSV_AV_SINGLE_HOST          0x0008
#define MSV_AV_TARGET_NAME          0x0009
#define MSV_AV_CHANNEL_BINDINGS     0x000a

typedef uint16_t av_pair_id_t;

/******************************************/
//             Utils Structs 
/******************************************/

typedef struct av_pair_t {
    av_pair_id_t av_id;
    uint16_t av_len;
    uint8_t *value;
} av_pair_t;

typedef struct ntlm_blob_t {
    uint32_t len;
    uint8_t *data;
} ntlm_blob_t;


typedef struct header_fields_t {
    uint16_t len;
    uint16_t max_len;
    uint32_t buffer_offset;
} header_fields_t;

/******************************************/
//       Structs for Msg's Headers
/******************************************/
typedef struct ntlm_negotiate_msg_header_t {
    ntlm_negotiate_flags_t negotiate_flags;

    header_fields_t domain_name_fields;
    header_fields_t workstation_fields;

    uint8_t version_present;
    uint64_t version;
} ntlm_negotiate_msg_header_t;


typedef struct ntlm_challenge_msg_header_t {
    header_fields_t target_name_fields;

    ntlm_negotiate_flags_t negotiate_flags;
    uint64_t server_challenge;

    uint64_t reserved;

    header_fields_t target_info_fields;

    uint8_t version_present;
    uint64_t version;
} ntlm_challenge_msg_header_t;


typedef struct ntlm_authenticate_msg_header_t {
    header_fields_t lm_challenge_resp_fields;
    header_fields_t nt_challenge_resp_fields;
    header_fields_t domain_name_fields;
    header_fields_t username_fields;
    header_fields_t workstation_fields;
    header_fields_t encrypted_random_session_key_fields;

    ntlm_negotiate_flags_t negotiate_flags;

    uint8_t version_present;
    uint64_t version;

    uint8_t mic_present;
    uint8_t mic[NTLM_HEADER_MIC_SIZE];
} ntlm_authenticate_msg_header_t;

/******* Header for messagges *******/
typedef struct ntlm_header_t {
    uint8_t signature[NTLM_HEADER_SIGNATURE_SIZE];
    ntlm_msg_type_t message_type;
    union {
        ntlm_negotiate_msg_header_t ntlm_negotiate_msg_header;
        ntlm_challenge_msg_header_t ntlm_challenge_msg_header;
        ntlm_authenticate_msg_header_t ntlm_authenticate_msg_header;
    } msg_header;
} ntlm_header_t;

/******************************************/
//       Structs for Msg's Payloads
/******************************************/

typedef struct ntlm_v2_client_challenge_t {
    uint8_t resp_type;
    uint8_t hi_resp_type;
    uint16_t reserved_1;
    uint32_t reserved_2;
    uint64_t time_stamp;
    uint64_t challenge_from_client;
    uint32_t reserved_3;

    size_t av_pairs_size;
    av_pair_t **av_pairs;
} ntlm_v2_client_challenge_t;

typedef struct ntlm_v2_response_t {
    uint8_t response[NTLM_V2_RESPONSE_SIZE];
    ntlm_v2_client_challenge_t ntlm_v2_client_challenge;
} ntlm_v2_response_t;

typedef struct ntlm_response_t {
    uint8_t response[NTLM_RESPONSE_SIZE];
} ntlm_response_t;

// In totale 24 Bytes
typedef struct lm_v2_response_t {
    uint8_t response[LM_V2_RESPONSE_SIZE];
    uint64_t challenge_from_client;
} lm_v2_response_t;

// In totale 24 Bytes
typedef struct lm_response_t {
    uint8_t response[LM_RESPONSE_SIZE];
} lm_response_t;


typedef struct ntlm_negotiate_msg_payload_t {
    ntlm_blob_t domain_name;
    ntlm_blob_t workstation_name;
} ntlm_negotiate_msg_payload_t;


typedef struct ntlm_challenge_msg_payload_t {
    ntlm_blob_t target_name;
    ntlm_blob_t target_info;
} ntlm_challenge_msg_payload_t;


typedef struct ntlm_authenticate_msg_payload_t {
    lm_response_type_t lm_response_type;
    ntlm_blob_t lm_challenge_response;

    ntlm_response_type_t ntlm_response_type;
    ntlm_blob_t nt_challenge_response;

    ntlm_blob_t domain_name;
    ntlm_blob_t username;
    ntlm_blob_t workstation_name;
    ntlm_blob_t encrypted_random_session_key;
} ntlm_authenticate_msg_payload_t;

/******************************************/
//             Main Msg Struct
/******************************************/
typedef struct ntlm_msg_t {
    ntlm_header_t header;

    // in base al tipo del messaggio in header
    union {
        ntlm_negotiate_msg_payload_t ntlm_negotiate_msg_payload;
        ntlm_challenge_msg_payload_t ntlm_challenge_msg_payload;
        ntlm_authenticate_msg_payload_t ntlm_authenticate_msg_payload;
    } payload;
    
} ntlm_msg_t;

/******************************************/
//            Buffer Context 
/******************************************/

typedef struct ntlm_buffer_ctx_t {
    const uint8_t *buf;
    size_t size;
    size_t offset;
} ntlm_buffer_ctx_t;

/******************************************/
//          Free function for Msg
/******************************************/

ntlm_parser_error free_ntlm_blob(ntlm_blob_t *blob) {
    if (!blob) return NTLM_PARSER_ERROR_INVALID_ARGS;

    if (blob->data) {
        free(blob->data);
    }
    blob->data = NULL;
    blob->len = 0;

    return NTLM_PARSER_OK;
}

ntlm_parser_error free_negotiate_msg(ntlm_msg_t *msg) {
    if (!msg) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (msg->header.message_type != NEGOTIATE_MESSAGE) return NTLM_PARSER_ERROR_FREE_INVALID_TYPE_MSG;

    ntlm_parser_error res;
    
    // Liberiamo Payload
    res = free_ntlm_blob(&msg->payload.ntlm_negotiate_msg_payload.domain_name);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_negotiate_msg_payload.workstation_name);
    if (res < NTLM_PARSER_OK) return res;
    
    // azzeriamo tutto
    memset(msg, 0, sizeof(*msg));

    return NTLM_PARSER_OK;
}

ntlm_parser_error free_challenge_msg(ntlm_msg_t *msg) {
    if (!msg) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (msg->header.message_type != CHALLENGE_MESSAGE) return NTLM_PARSER_ERROR_FREE_INVALID_TYPE_MSG;

    ntlm_parser_error res;

    // Liberiamo Payload
    res = free_ntlm_blob(&msg->payload.ntlm_challenge_msg_payload.target_info);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_challenge_msg_payload.target_name);
    if (res < NTLM_PARSER_OK) return res;

    memset(msg, 0, sizeof(*msg));

    return NTLM_PARSER_OK;
}

ntlm_parser_error free_authenticate_msg(ntlm_msg_t *msg) {
    if (!msg) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (msg->header.message_type != AUTHENTICATE_MESSAGE) return NTLM_PARSER_ERROR_FREE_INVALID_TYPE_MSG;

    ntlm_parser_error res;

    // Liberiamo Payload
    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.lm_challenge_response);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.nt_challenge_response);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.domain_name);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.username);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.workstation_name);
    if (res < NTLM_PARSER_OK) return res;

    res = free_ntlm_blob(&msg->payload.ntlm_authenticate_msg_payload.encrypted_random_session_key);
    if (res < NTLM_PARSER_OK) return res;

    memset(msg, 0, sizeof(*msg));

    return NTLM_PARSER_OK;
}

ntlm_parser_error free_ntlm_msg(ntlm_msg_t *msg) {
    if (!msg) return NTLM_PARSER_ERROR_INVALID_ARGS;
    ntlm_parser_error res;

    switch (msg->header.message_type) {
        case NEGOTIATE_MESSAGE:
            res = free_negotiate_msg(msg);
            if (res < NTLM_PARSER_OK) return res;
            break;

        case CHALLENGE_MESSAGE:
            res = free_challenge_msg(msg);
            if (res < NTLM_PARSER_OK) return res;
            break;

        case AUTHENTICATE_MESSAGE:
            res = free_authenticate_msg(msg);
            if (res < NTLM_PARSER_OK) return res;
            break;

        default:
            return NTLM_PARSER_ERROR_INVALID_MSG_TYPE;
    }

    return NTLM_PARSER_OK;
}

/******************************************/
//              Utils CTX BUffer
/******************************************/

ntlm_parser_error ntlm_ctx_buffer_init(const uint8_t *buffer, size_t len, ntlm_buffer_ctx_t *out) {
    if (!buffer || !*buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    out->buf = buffer;
    out->size = len;
    out->offset = 0;

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_is_valid(ntlm_buffer_ctx_t *ctx_buffer) {
    if (!ctx_buffer) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (!ctx_buffer->buf) return NTLM_PARSER_ERROR_INVALID_CTX_BUFFER;

    if (ctx_buffer->offset > ctx_buffer->size) return NTLM_PARSER_ERROR_INVALID_CTX_BUFFER;

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buff_safe_incr_offset(ntlm_buffer_ctx_t *ctx_buffer, size_t incr) {
    if (!ctx_buffer) return NTLM_PARSER_ERROR_INVALID_ARGS;

    if (incr > ctx_buffer->size - ctx_buffer->offset 
        || ctx_buffer->offset + incr > ctx_buffer->size) return NTLM_PARSER_ERROR_OFFSET_OVERFLOW;

    ctx_buffer->offset += incr;

    return NTLM_PARSER_OK;
}


ntlm_parser_error ntlm_ctx_buffer_check_safe_read(ntlm_buffer_ctx_t *ctx_buffer, size_t bytes_to_read) {
    if (!ctx_buffer) return NTLM_PARSER_ERROR_INVALID_ARGS;

    // Verifichaimo se la read è safe
    if (bytes_to_read > ctx_buffer->size - ctx_buffer->offset 
        || ctx_buffer->offset + bytes_to_read > ctx_buffer->size) return NTLM_PARSER_ERROR_READ_OVERFLOW;
    
    return NTLM_PARSER_OK;
}

/******************** Helper functions for Read from Buffer ***************************/
// Incrementano offset di ctx_buffer

// Funzioni di read assumono input valido
void read_u16(const uint8_t *buff, uint16_t *out) {
    *out = ((uint16_t)buff[1] << 8)
           |((uint16_t)buff[0]);
}

void read_u16_le(const uint8_t *buff, uint16_t *out) {
    *out = (uint16_t)(buff[0])
           | (((uint16_t)buff[1]) << 8);   
}

void read_u32(const uint8_t *buff, uint32_t *out) {
    *out = ((uint32_t)buff[3] << 24)
           | ((uint32_t)buff[2] << 16)
           | ((uint32_t)buff[1] << 8)
           | (uint32_t)buff[0];
}

void read_u32_le(const uint8_t *buff, uint32_t *out) {
    *out = (uint32_t)(buff[0])
           | ((uint32_t)buff[1] << 8)
           | ((uint32_t)buff[2] << 16)
           | ((uint32_t)buff[3] << 24);
}

void read_u64(const uint8_t *buff, uint64_t *out) {
    *out = ((uint64_t)buff[7] << 56)
           | ((uint64_t)buff[6] << 48)
           | ((uint64_t)buff[5] << 40)
           | ((uint64_t)buff[4] << 32)
           | ((uint64_t)buff[3] << 24)
           | ((uint64_t)buff[2] << 16)
           | ((uint64_t)buff[1] << 8)
           | ((uint64_t)buff[0]);
}

void read_u64_le(const uint8_t *buff, uint64_t *out) {
    *out = (uint64_t)buff[0]
           | ((uint64_t)buff[1] << 8)
           | ((uint64_t)buff[2] << 16)
           | ((uint64_t)buff[3] << 24)
           | ((uint64_t)buff[4] << 32)
           | ((uint64_t)buff[5] << 40)
           | ((uint64_t)buff[6] << 48)
           | ((uint64_t)buff[7] << 56);
}

// Normal read. non little-endian
ntlm_parser_error ntlm_ctx_buffer_read_u16(ntlm_buffer_ctx_t *ctx_buffer, uint16_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 2 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    size_t offset = ctx_buffer->offset;
    read_u16(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_read_u16_le(ntlm_buffer_ctx_t *ctx_buffer, uint16_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 2 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    size_t offset = ctx_buffer->offset;
    read_u16_le(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

// Normal read. non little-endian
ntlm_parser_error ntlm_ctx_buffer_read_u32(ntlm_buffer_ctx_t *ctx_buffer, uint32_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 4 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    read_u32(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_read_u32_le(ntlm_buffer_ctx_t *ctx_buffer, uint32_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 4 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    read_u32_le(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

// Normal read. non little-endian
ntlm_parser_error ntlm_ctx_buffer_read_u64(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 8 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    read_u64(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_read_u64_le(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 8 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    read_u64_le(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

/******************************************/
//        Utils header_fields struct
/******************************************/

/**
 * Valida un header_fields dato un ctx_buffer
 */
ntlm_parser_error header_fields_is_valid(ntlm_buffer_ctx_t *ctx_buffer, header_fields_t *fields) {
    if (!ctx_buffer || !fields) return NTLM_PARSER_ERROR_INVALID_ARGS;

    if (fields->len > NTLM_BLOB_MAX_LEN) return NTLM_PARSER_ERROR_MAX_LEN_BLOB_EXEEDED;
    if (fields->max_len > NTLM_BLOB_MAX_LEN) return NTLM_PARSER_ERROR_MAX_LEN_BLOB_EXEEDED;
    if (fields->buffer_offset > ctx_buffer->size) return NTLM_PARSER_ERROR_OFFSET_OVERFLOW;

    // Verificare che len + offset non vada in overflow
    if (fields->buffer_offset + fields->len > ctx_buffer->size) return NTLM_PARSER_ERROR_BUFF_OVERFLOW;

    return NTLM_PARSER_OK;
}

/******************************************/
//               Generic Utils 
/******************************************/

ntlm_parser_error check_signature(const uint8_t *signature) {
    if (!signature) return NTLM_PARSER_ERROR_INVALID_ARGS;

    for (size_t i = 0; i < NTLM_HEADER_SIGNATURE_SIZE; i++) {
        if (signature[i] != ntlm_protocol_sign[i]) return NTLM_PARSER_ERROR_INVALID_SIGNATURE;
    }

    return NTLM_PARSER_OK;
}

ntlm_parser_error check_msg_type(ntlm_msg_type_t type) {
    if (type == CHALLENGE_MESSAGE 
    || type == NEGOTIATE_MESSAGE 
    || type == AUTHENTICATE_MESSAGE) return NTLM_PARSER_OK;

    return NTLM_PARSER_ERROR_INVALID_MSG_TYPE;
}

uint8_t is_vector_empty(uint8_t *v, size_t size) {
    size_t sum = 0;
    for (int i = 0; i < size; i++)
        sum |= v[i];
    
    return sum == 0 ? 0 : 1;
}

uint8_t is_version_present(uint8_t *version) {
    return is_vector_empty(version, NTLM_HEADER_VERSION_SIZE);
}

uint8_t is_mic_present(uint8_t *mic) {
    return is_vector_empty(mic, NTLM_HEADER_MIC_SIZE);
}

/******************************************/
//           Parse functions
/******************************************/

/************************ For Header ************************/

ntlm_parser_error header_fields_parse(ntlm_buffer_ctx_t *ctx_buffer, header_fields_t *fields) {
    if (!ctx_buffer || !fields) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;

    // Leggiamo e verifichaimo Len, MaxLen e BufferOffset
    if ((res = ntlm_ctx_buffer_read_u16_le(ctx_buffer, &fields->len)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u16_le(ctx_buffer, &fields->max_len)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u32_le(ctx_buffer, &fields->buffer_offset)) < NTLM_PARSER_OK) return res;
    
    if ((res = header_fields_is_valid(ctx_buffer, fields)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_4_bytes_header_parse_le(ntlm_buffer_ctx_t *ctx_buffer, uint32_t *dest) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_read_u32_le(ctx_buffer, dest)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_8_bytes_header_parse_le(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *dest) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_read_u64_le(ctx_buffer, dest)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_8_bytes_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *dest) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_read_u64(ctx_buffer, dest)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_n_bytes_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *dest, size_t len) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, len)) < NTLM_PARSER_OK) return res;
    memcpy(dest, &ctx_buffer->buf[ctx_buffer->offset], len);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, len)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_negotiate_flags_parse(ntlm_buffer_ctx_t *ctx_buffer, ntlm_negotiate_flags_t *flags) {
    return generic_4_bytes_header_parse_le(ctx_buffer, flags);
}

ntlm_parser_error msg_type_header_parse(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_type_t *type) {
    return generic_4_bytes_header_parse_le(ctx_buffer, type);
}

ntlm_parser_error version_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *version) {
    return generic_8_bytes_header_parse(ctx_buffer, version);
}

ntlm_parser_error server_challenge_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *s_c) {
    return generic_8_bytes_header_parse(ctx_buffer, s_c); 
}

ntlm_parser_error reserved_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *reserved) {
    return generic_8_bytes_header_parse(ctx_buffer, reserved); 
}

ntlm_parser_error mic_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *mic) {
    return generic_n_bytes_header_parse(ctx_buffer, mic, NTLM_HEADER_MIC_SIZE);
}

ntlm_parser_error signature_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *signature) {
    return generic_n_bytes_header_parse(ctx_buffer, signature, NTLM_HEADER_SIGNATURE_SIZE);
}

/************************ For Payload ************************/

ntlm_parser_error ntlm_blob_alloc(ntlm_blob_t *blob, size_t len) {
    if (!blob) return NTLM_PARSER_ERROR_INVALID_ARGS;

    // Per sicurezza, per evitare memeory leak
    if (blob->data) {
        free(blob->data);
        blob->len = 0;
        blob->data = NULL;
    }

    blob->data = malloc(sizeof(uint8_t) * len);
    if (!blob->data) {
        return NTLM_PARSER_ERROR_ALLOC_BLOB;
    }

    blob->len = len;

    return NTLM_PARSER_OK;
}

ntlm_parser_error header_fields_payload_parse(ntlm_buffer_ctx_t *ctx_buffer, header_fields_t *header, ntlm_blob_t *blob) {
    if (!ctx_buffer || !header || !blob) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    
    if ((res = header_fields_is_valid(ctx_buffer, header)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_blob_alloc(blob, header->len)) < NTLM_PARSER_OK) return res;

    memcpy(blob->data, &ctx_buffer->buf[header->buffer_offset], header->len);

    return NTLM_PARSER_OK;
}

/********* Parsing per campi payload specifici *********/

ntlm_parser_error parse_av_pair(ntlm_buffer_ctx_t *ctx_buffer, av_pair_t **av_pair) {
    
}

ntlm_parser_error parse_av_pairs(ntlm_buffer_ctx_t *ctx_buffer, av_pair_t **av_pairs, size_t out_size) {
    
}

ntlm_parser_error ntlm_v2_response_payload_parse(ntlm_buffer_ctx_t *ctx_buffer, ntlm_v2_response_t *resp) {
    
}

ntlm_parser_error ntlm_response_payload_parse(ntlm_blob_t *blob, ntlm_response_t *resp) {}

ntlm_parser_error lm_v2_response_payload_parse(ntlm_blob_t *blob, lm_v2_response_t *resp) {}

ntlm_parser_error lm_response_response_payload_parse(ntlm_blob_t *blob, lm_response_t *resp) {}


/******************************************/
//           Main Parse Functions
/******************************************/

ntlm_parser_error parse_ntlm_msg_payload_negotiate(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_negotiate_msg_payload_t *p = &msg->payload.ntlm_negotiate_msg_payload;
    ntlm_negotiate_msg_header_t *h = &msg->header.msg_header.ntlm_negotiate_msg_header;

    // Parsiamo DomainName, WorkstationName 
    if ((res = header_fields_payload_parse(ctx_buffer, &h->domain_name_fields, &p->domain_name)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->workstation_fields, &p->workstation_name)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_payload_challenge(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_challenge_msg_payload_t *p = &msg->payload.ntlm_challenge_msg_payload;
    ntlm_challenge_msg_header_t *h = &msg->header.msg_header.ntlm_challenge_msg_header;

    // Parsiamo TargetName, TargetInfo
    if ((res = header_fields_payload_parse(ctx_buffer, &h->target_name_fields, &p->target_name)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->target_info_fields, &p->target_info)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_payload_authenticate(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_authenticate_msg_payload_t *p = &msg->payload.ntlm_authenticate_msg_payload;
    ntlm_authenticate_msg_header_t *h = &msg->header.msg_header.ntlm_authenticate_msg_header;

    // Parsiamo LmChallengeResponse, NtChallengeResponse, DomainName,
    // UserName, Workstation, EncryptedRandomSessionKey 
    if ((res = header_fields_payload_parse(ctx_buffer, &h->lm_challenge_resp_fields, &p->lm_challenge_response)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->nt_challenge_resp_fields, &p->nt_challenge_response)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->domain_name_fields, &p->domain_name)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->username_fields, &p->username)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->workstation_fields, &p->workstation_name)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_payload_parse(ctx_buffer, &h->encrypted_random_session_key_fields, &p->encrypted_random_session_key)) < NTLM_PARSER_OK) return res;

    if (p->nt_challenge_response.len == NTLM_RESPONSE_SIZE) {
        p->ntlm_response_type = NTLM_RESPONSE_V1;
        p->lm_response_type = LM_RESPONSE_V1;
    } else if (p->nt_challenge_response.len > NTLM_RESPONSE_SIZE) {
        p->ntlm_response_type = NTLM_RESPONSE_V2;
        p->lm_response_type = LM_RESPONSE_V2;
    } else {
        return NTLM_PARSER_ERROR_INVALID_NTLM_RESPONSE_SIZE;
    }
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_payload(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;

    switch (msg->header.message_type) {
        case NEGOTIATE_MESSAGE:
            if ((res = parse_ntlm_msg_payload_negotiate(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;

        case CHALLENGE_MESSAGE:
            if ((res = parse_ntlm_msg_payload_challenge(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;

        case AUTHENTICATE_MESSAGE:
            if ((res = parse_ntlm_msg_payload_authenticate(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;
        
        default:
            return NTLM_PARSER_ERROR_INVALID_MSG_TYPE;
    }

    return NTLM_PARSER_OK;
}


/********************* Header Parser **************************/

ntlm_parser_error parse_ntlm_msg_header_negotiate(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_negotiate_msg_header_t *h = &msg->header.msg_header.ntlm_negotiate_msg_header;

    // Parsiamo NegotiateFlags, DomainNameFields, WorkstationFields e Version
    if ((res = ntlm_negotiate_flags_parse(ctx_buffer, &h->negotiate_flags)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->domain_name_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->workstation_fields)) < NTLM_PARSER_OK) return res;
    if ((res = version_header_parse(ctx_buffer, &h->version)) < NTLM_PARSER_OK) return res;

    if (h->version != 0)
        h->version_present = 1;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_header_challenge(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_challenge_msg_header_t *h = &msg->header.msg_header.ntlm_challenge_msg_header;

    // Parsiamo TargetNameFields, NegotiateFlags, ServerChallenge, Reserved, TargetInfoFields e version
    if ((res = header_fields_parse(ctx_buffer, &h->target_name_fields)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_negotiate_flags_parse(ctx_buffer, &h->negotiate_flags)) < NTLM_PARSER_OK) return res;
    if ((res = server_challenge_header_parse(ctx_buffer, &h->server_challenge)) < NTLM_PARSER_OK) return res;
    if ((res = reserved_header_parse(ctx_buffer, &h->reserved)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->target_info_fields)) < NTLM_PARSER_OK) return res;
    if ((res = version_header_parse(ctx_buffer, &h->version)) < NTLM_PARSER_OK) return res;

    if (h->version != 0)
        h->version_present = 1;

    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_header_authenticate(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    ntlm_authenticate_msg_header_t *h = &msg->header.msg_header.ntlm_authenticate_msg_header;

    // Parsiamo LmChallengeResponseFields, NtChallengeResponseFields, DomainNameFields,
    // UserNameFields, WorkstationFields, EncryptedRandomSessionKeyFields,
    // NegotiateFlags, Version e MIC
    if ((res = header_fields_parse(ctx_buffer, &h->lm_challenge_resp_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->nt_challenge_resp_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->domain_name_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->username_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->workstation_fields)) < NTLM_PARSER_OK) return res;
    if ((res = header_fields_parse(ctx_buffer, &h->encrypted_random_session_key_fields)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_negotiate_flags_parse(ctx_buffer, &h->negotiate_flags)) < NTLM_PARSER_OK) return res;
    if ((res = version_header_parse(ctx_buffer, &h->version)) < NTLM_PARSER_OK) return res;
    if ((res = mic_header_parse(ctx_buffer, h->mic)) < NTLM_PARSER_OK) return res;

    if (h->version != 0)
        h->version_present = 1;

    if (is_mic_present(h->mic))
        h->mic_present = 1;

    return NTLM_PARSER_OK;
}

ntlm_parser_error parse_ntlm_msg_header(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    switch (msg->header.message_type) {
        case NEGOTIATE_MESSAGE:
            if ((res = parse_ntlm_msg_header_negotiate(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;
        
        case CHALLENGE_MESSAGE:
            if ((res = parse_ntlm_msg_header_challenge(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;

        case AUTHENTICATE_MESSAGE:
            if ((res = parse_ntlm_msg_header_authenticate(ctx_buffer, msg)) < NTLM_PARSER_OK)
                return res;
            break;
        
        default:
            return NTLM_PARSER_ERROR_INVALID_MSG_TYPE;
    }

    return NTLM_PARSER_OK;
}

/********************* Main Parser **************************/

ntlm_parser_error parse_ntlm_msg(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg) {
    if (!ctx_buffer || !msg) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (ctx_buffer->size > NTLM_MAX_MSG_DIM) return NTLM_PARSER_ERROR_BUFF_TOO_BIG;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;

    // Resetta msg
    memset(msg, 0, sizeof(ntlm_msg_t));
    
    // Leggiamo Signature e type
    if ((res = signature_header_parse(ctx_buffer, msg->header.signature)) < NTLM_PARSER_OK) return res;
    if ((res = msg_type_header_parse(ctx_buffer, &msg->header.message_type)) < NTLM_PARSER_OK) return res;

    // Parsiamo header e payload
    if ((res = parse_ntlm_msg_header(ctx_buffer, msg)) < NTLM_PARSER_OK) return res;
    if ((res = parse_ntlm_msg_payload(ctx_buffer, msg)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

/******************************************/
//           Getter Helper functions
/******************************************/


int main() {

    const uint8_t ntlm_negotiate[] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
        0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
        0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f
    };
    

    const uint8_t ntlm_challenge[] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x15, 0x82, 0x89, 0xe2, 0xc4, 0xba, 0x87, 0xa2, 0x65, 0xde, 0x9e, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x9a, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x05, 0x02, 0xce, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00,
        0x02, 0x00, 0x08, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x01, 0x00, 0x1e, 0x00,
        0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00, 0x34, 0x00,
        0x55, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00, 0x04, 0x00,
        0x34, 0x00, 0x57, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00,
        0x34, 0x00, 0x55, 0x00, 0x4d, 0x00, 0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00,
        0x2e, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00,
        0x43, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x03, 0x00, 0x14, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00,
        0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x05, 0x00,
        0x14, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00,
        0x43, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const uint8_t ntlm_authenticate[] = {
        0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
        0x58, 0x00, 0x00, 0x00, 0x36, 0x01, 0x36, 0x01, 0x70, 0x00, 0x00, 0x00, 0x12, 0x00, 0x12, 0x00,
        0xa6, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x22, 0x00, 0x22, 0x00,
        0xbe, 0x01, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
        0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x01, 0x58, 0x1d, 0x5b, 0x64, 0x84, 0xbf, 0x86,
        0x99, 0x09, 0x64, 0xe6, 0x49, 0x13, 0x08, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x1e, 0x69, 0xad, 0x14, 0x8b, 0x55, 0x9a, 0x1a, 0x34, 0xcb, 0x95, 0x26, 0x20, 0xc5, 0xc8, 0x36,
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x18, 0x72, 0x02, 0xcc, 0x8a, 0xdc, 0x01,
        0xd0, 0x9c, 0xd6, 0x0b, 0x64, 0xff, 0x26, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00,
        0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x57, 0x00, 0x49, 0x00,
        0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00, 0x34, 0x00, 0x55, 0x00, 0x4d, 0x00,
        0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00, 0x04, 0x00, 0x34, 0x00, 0x57, 0x00,
        0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00, 0x34, 0x00, 0x55, 0x00,
        0x4d, 0x00, 0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00, 0x2e, 0x00, 0x38, 0x00,
        0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00,
        0x4c, 0x00, 0x03, 0x00, 0x14, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00,
        0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x05, 0x00, 0x14, 0x00, 0x38, 0x00,
        0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00,
        0x4c, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x09, 0x2b, 0x4f, 0x13, 0x3a, 0xc9, 0xcf, 0x9f, 0xb6,
        0x47, 0xdc, 0x6c, 0xa6, 0x4f, 0x41, 0x8a, 0x12, 0xff, 0xb0, 0xa6, 0x57, 0xd2, 0xb9, 0x5b, 0xd6,
        0x7d, 0x7f, 0xc9, 0xa2, 0xac, 0x8f, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x24, 0x00, 0x63, 0x00,
        0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00,
        0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x34, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x32, 0x00,
        0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, 0x47, 0x00,
        0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x61, 0x00, 0x31, 0x00, 0x34, 0x00, 0x4b, 0x00,
        0x41, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00,
        0x2d, 0x00, 0x32, 0x00, 0x30, 0x00, 0x32, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x32, 0x00,
        0xd9, 0x34, 0x25, 0xe6, 0x04, 0x32, 0xc4, 0x60, 0xf2, 0x7e, 0x1c, 0xa5, 0x35, 0xbe, 0xf6, 0x22
    };

    ntlm_msg_t msg;
    ntlm_parser_error res;

    ntlm_buffer_ctx_t ctx_buffer;
    res = ntlm_ctx_buffer_init(ntlm_authenticate, 496, &ctx_buffer);

    if (res < NTLM_PARSER_OK) {
        printf("Errore: 0x%x\n", res);
        return 1;
    }

    res = parse_ntlm_msg(&ctx_buffer, &msg);

    if (res < NTLM_PARSER_OK) {
        printf("Errore: 0x%x\n", res);
        return 1;
    }

    printf("Signature: %s (", msg.header.signature);
    for (size_t i = 0; i < NTLM_HEADER_SIGNATURE_SIZE; i++) {
        printf("0x%x ", msg.header.signature[i]);
    }
    printf(")\n");

    printf("MsgType: %d (0x%x)\n", msg.header.message_type, msg.header.message_type);

    if (msg.header.message_type == NEGOTIATE_MESSAGE){
        printf("NegFlags: 0x%x\n", msg.header.msg_header.ntlm_negotiate_msg_header.negotiate_flags);

        printf("DomainNameFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.domain_name_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.domain_name_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.domain_name_fields.buffer_offset);

        printf("WorkstationFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.workstation_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.workstation_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_negotiate_msg_header.workstation_fields.buffer_offset);

        if (msg.header.msg_header.ntlm_negotiate_msg_header.version_present) {
            printf("Version: 0x%lx\n", msg.header.msg_header.ntlm_negotiate_msg_header.version);
            
        }
        else {
            printf("Version: None\n");
        }

        printf("DomainName Payload :");
        for (size_t i = 0; i < msg.payload.ntlm_negotiate_msg_payload.domain_name.len; i++) {
            printf("0x%x ", msg.payload.ntlm_negotiate_msg_payload.domain_name.data[i]);
        }
        printf("\n");

        printf("WorkstationName Payload :");
        for (size_t i = 0; i < msg.payload.ntlm_negotiate_msg_payload.workstation_name.len; i++) {
            printf("0x%x ", msg.payload.ntlm_negotiate_msg_payload.workstation_name.data[i]);
        }
        printf("\n");
    }
    else if (msg.header.message_type == CHALLENGE_MESSAGE) {
        printf("TargetNameFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_name_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_name_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_name_fields.buffer_offset);

        printf("NegFlags: 0x%x\n", msg.header.msg_header.ntlm_challenge_msg_header.negotiate_flags);

        printf("ServerChallenge: 0x%lx\n", msg.header.msg_header.ntlm_challenge_msg_header.server_challenge);
        printf("Reserved: %s\n", msg.header.msg_header.ntlm_challenge_msg_header.reserved);

        printf("TargetInfoFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_info_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_info_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_challenge_msg_header.target_info_fields.buffer_offset);

        if (msg.header.msg_header.ntlm_challenge_msg_header.version_present) {
            printf("Version: 0x%lx\n", msg.header.msg_header.ntlm_challenge_msg_header.version);
            
        }
        else {
            printf("Version: None\n");
        }

        printf("TargetName Payload :");
        for (size_t i = 0; i < msg.payload.ntlm_challenge_msg_payload.target_name.len; i++) {
            printf("0x%x ", msg.payload.ntlm_challenge_msg_payload.target_name.data[i]);
        }
        printf("\n");

        printf("TargetInfo Payload :");
        for (size_t i = 0; i < msg.payload.ntlm_challenge_msg_payload.target_info.len; i++) {
            printf("0x%x ", msg.payload.ntlm_challenge_msg_payload.target_info.data[i]);
        }
        printf("\n");
    } 
    else {
        printf("LmChallengeResponseFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.lm_challenge_resp_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.lm_challenge_resp_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.lm_challenge_resp_fields.buffer_offset);

        printf("NtChallengeResponseFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.nt_challenge_resp_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.nt_challenge_resp_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.nt_challenge_resp_fields.buffer_offset);

        printf("DomainNameFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.domain_name_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.domain_name_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.domain_name_fields.buffer_offset);

        printf("UserNameFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.username_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.username_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.username_fields.buffer_offset);

        printf("WorkstationFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.workstation_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.workstation_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.workstation_fields.buffer_offset);

        printf("EncryptedRandomSessionKeyFields:\n");
        printf("\t len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.encrypted_random_session_key_fields.len);
        printf("\t max_len: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.encrypted_random_session_key_fields.max_len);
        printf("\t offset: %d\n", msg.header.msg_header.ntlm_authenticate_msg_header.encrypted_random_session_key_fields.buffer_offset);

        printf("NegFlags: 0x%x\n", msg.header.msg_header.ntlm_authenticate_msg_header.negotiate_flags);

        if (msg.header.msg_header.ntlm_authenticate_msg_header.version_present) {
            printf("Version: 0x%lx\n", msg.header.msg_header.ntlm_authenticate_msg_header.version);
            
        }
        else {
            printf("Version: None\n");
        }

        if (msg.header.msg_header.ntlm_authenticate_msg_header.mic_present) {
            printf("MIC: ");
            for (size_t i = 0; i < NTLM_HEADER_MIC_SIZE; i++) {
                printf("0x%x ", msg.header.msg_header.ntlm_authenticate_msg_header.mic[i]);
            }
            printf("\n");
        }
        else {
            printf("MIC: None\n");
        }

        printf("LmChallengeResponse Payload: ");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.lm_challenge_response.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.lm_challenge_response.data[i]);
            }
            printf("\n");

        printf("NtChallengeResponse Payload:");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.nt_challenge_response.data[i]);
            }
            printf("\n");

        printf("DomainName Payload:");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.domain_name.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.domain_name.data[i]);
            }
            printf("\n");

        printf("UserName Payload:");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.username.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.username.data[i]);
            }
            printf("\n");

        printf("Workstation Payload:");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.workstation_name.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.workstation_name.data[i]);
            }
            printf("\n");

        printf("EncryptedRandomSessionKey Payload:");
        for (size_t i = 0; i < msg.payload.ntlm_authenticate_msg_payload.encrypted_random_session_key.len; i++) {
                printf("0x%x ", msg.payload.ntlm_authenticate_msg_payload.encrypted_random_session_key.data[i]);
            }
            printf("\n");
    }

    printf("OK\n");

    free_ntlm_msg(&msg);

    return 0;
}
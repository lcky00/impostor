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

#define LM_V2_RESPONSE_SIZE                     16              // 16 Bytes
#define LM_RESPONSE_SIZE                        24              // 24 Bytes

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

typedef struct ntlm_v2_response_t {
    uint8_t response[NTLM_V2_RESPONSE_SIZE];
    ntlm_blob_t ntlm_v2_client_challenge;
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
    union {
        lm_response_t lm_response;
        lm_v2_response_t lm_v2_response;
    } lm_challenge_response;

    ntlm_response_type_t ntlm_response_type;
    union {
        ntlm_response_t ntlm_response;
        ntlm_v2_response_t ntlm_v2_response;
    } nt_challenge_response;

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

ntlm_parser_error ntlm_ctx_buffer_read_u16_le(ntlm_buffer_ctx_t *ctx_buffer, uint16_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 2 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    size_t offset = ctx_buffer->offset;
    *out = (uint16_t)(ctx_buffer->buf[offset])
           | (((uint16_t)ctx_buffer->buf[offset + 1]) << 8);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint16_t))) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_read_u32_le(ntlm_buffer_ctx_t *ctx_buffer, uint32_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 4 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    *out = (uint32_t)(ctx_buffer->buf[offset])
           | ((uint32_t)ctx_buffer->buf[offset + 1] << 8)
           | ((uint32_t)ctx_buffer->buf[offset + 2] << 16)
           | ((uint32_t)ctx_buffer->buf[offset + 3] << 24);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint32_t))) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_ctx_buffer_read_u64_le(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 8 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

    size_t offset = ctx_buffer->offset;
    *out = (uint64_t)ctx_buffer->buf[offset]
           | ((uint64_t)ctx_buffer->buf[offset + 1] << 8)
           | ((uint64_t)ctx_buffer->buf[offset + 2] << 16)
           | ((uint64_t)ctx_buffer->buf[offset + 3] << 24)
           | ((uint64_t)ctx_buffer->buf[offset + 4] << 32)
           | ((uint64_t)ctx_buffer->buf[offset + 5] << 40)
           | ((uint64_t)ctx_buffer->buf[offset + 6] << 48)
           | ((uint64_t)ctx_buffer->buf[offset + 7] << 56);

    if ((res = safe_incr_ctx_buff_offset(ctx_buffer, sizeof(uint64_t))) < NTLM_PARSER_OK) return res;

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

ntlm_parser_error generic_4_bytes_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint32_t *dest) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_read_u32_le(ctx_buffer, dest)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_8_bytes_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint64_t *dest) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_read_u64_le(ctx_buffer, dest)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error generic_n_bytes_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *dest, size_t len) {
    if (!ctx_buffer || !dest) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, len)) < NTLM_PARSER_OK) return res;
    memcpy(dest, ctx_buffer->buf[ctx_buffer->offset], len);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, len)) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_negotiate_flags_parse(ntlm_buffer_ctx_t *ctx_buffer, ntlm_negotiate_flags_t *flags) {
    return generic_4_bytes_header_parse(ctx_buffer, flags);
}

ntlm_parser_error msg_type_header_parse(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_type_t *type) {
    return generic_4_bytes_header_parse(ctx_buffer, type);
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

    memcpy(blob->data, ctx_buffer->buf[header->buffer_offset], header->len);

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_v2_response_payload_parse(ntlm_buffer_ctx_t *ctx_buffer, header_fields_t *header, ntlm_v2_response_t *resp) {
    if (!ctx_buffer || !header || !resp) return NTLM_PARSER_ERROR_INVALID_ARGS;
}
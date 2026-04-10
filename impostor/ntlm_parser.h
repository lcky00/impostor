#ifndef NTLM_PARSER_H
#define NTLM_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>

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
#define NTLM_PARSER_ERROR_MAX_AV_PAIR_REACHED           0x80000013
#define NTLM_PARSER_ERROR_LEN_AV_PAIR                   0x80000014
#define NTLM_PARSER_ERROR_CONVERSION                    0x80000015    

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

#define NTLM_MAX_AV_PAIRS 128

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
//            NTLM DECODE
/******************************************/

typedef struct av_pair_t {
    av_pair_id_t av_id;
    uint16_t av_len;
    uint8_t *value;
} av_pair_t;

typedef struct ntlm_v2_client_challenge_t {
    uint8_t resp_type;
    uint8_t hi_resp_type;
    uint16_t reserved_1;
    uint32_t reserved_2;
    uint64_t time_stamp;
    uint64_t challenge_from_client;
    uint32_t reserved_3;

    size_t av_pairs_size;
    size_t av_pairs_dim;
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

/******************************************/
//             Public API
/******************************************/

/* Initialization & Main Parsing */
ntlm_parser_error ntlm_ctx_buffer_init(const uint8_t *buffer, size_t len, ntlm_buffer_ctx_t *out);
ntlm_parser_error parse_ntlm_msg(ntlm_buffer_ctx_t *ctx_buffer, ntlm_msg_t *msg);

/* Decoders for specific payloads */
ntlm_parser_error target_info_payload_parse(ntlm_blob_t *blob, av_pair_t ***av_pairs, size_t *out_size, size_t *out_dim);
ntlm_parser_error ntlm_v2_response_payload_parse(ntlm_blob_t *blob, ntlm_v2_response_t *resp);
ntlm_parser_error lm_v2_response_payload_parse(ntlm_blob_t *blob, lm_v2_response_t *resp);

/* Memory Management */
ntlm_parser_error free_ntlm_msg(ntlm_msg_t *msg);
void ntlm_av_pairs_free(av_pair_t ***av_pairs, size_t len);

/* Debugging & Utils */
typedef void (*ntlm_logger_t)(const char *format, va_list args);

void set_ntlm_logger(ntlm_logger_t logger_cb);

void ntlm_log(const char *format, ...);
ntlm_parser_error dump_msg(ntlm_msg_t *msg);
ntlm_parser_error dump_av_pairs(av_pair_t **av_pairs, size_t size);
ntlm_parser_error dump_utf16_le_string(const uint8_t *data, size_t len);

#endif // NTLM_PARSER_H
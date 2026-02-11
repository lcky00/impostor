/**
 * Parser for NTLM Authentication Protocol
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/907f519d-6217-45b1-b421-dca10fc8af0d
 * 
 * Luca Vinci <luca9vinci at gmail dot com>
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NLMP_PARSER_OK 0x00000000
#define NLMP_PARSER_ERROR_INVALID_ARGS 0x80000001
#define NLMP_PARSER_ERROR_INVALID_SIGNATURE 0x80000002
#define NLMP_PARSER_ERROR_INVALID_MSG_TYPE 0x80000003
#define NLMP_PARSER_ERROR_BUFF_OVERFLOW 0x80000004

typedef int32_t nlmp_parser_error;

#define NLMP_HEADER_SIGNATURE_DIM      8     // 8 Bytes
#define NLMP_HEADER_MIC_DIM            16    // 16 Bytes

#define NLMP_HEADER_FIELDS_STRUCT_DIM  8     // 8 Bytes - 64 bit

#define NEGOTIATE_MESSAGE    0x00000001
#define CHALLENGE_MESSAGE    0x00000002
#define AUTHENTICATE_MESSAGE 0x00000003

typedef uint32_t nlmp_msg_type_t;
typedef uint64_t nlmp_msg_version;
typedef uint8_t * nlmp_msg_payload_t;

uint8_t ntml_protocol_sign[NLMP_HEADER_SIGNATURE_DIM] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};

/* NegFlags*/
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
//       Structs for Msg's Headers
/******************************************/

typedef struct header_fields_t {
    uint16_t len;
    uint16_t max_len;
    uint32_t buffer_offset;
} header_fields_t;


typedef struct nlmp_negotiate_msg_header_t {
    uint32_t negotiate_flags;
    header_fields_t domain_name_fields;
    header_fields_t workstation_fields;
    nlmp_msg_version version;
} nlmp_negotiate_msg_header_t;


typedef struct nlmp_challenge_msg_header_t {
    header_fields_t target_name_fields;
    uint32_t negotiate_flags;
    uint64_t server_challenge;
    uint64_t reserved;
    header_fields_t target_info_fields;
    nlmp_msg_version version;
} nlmp_challenge_msg_header_t;


typedef struct nlmp_authenticate_msg_header_t {
    header_fields_t lm_challenge_resp_fields;
    header_fields_t nt_challenge_resp_fields;
    header_fields_t domain_name_fields;
    header_fields_t username_fields;
    header_fields_t workstation_fields;
    header_fields_t encrypted_random_session_key_fields;
    uint32_t negotiate_flags;
    nlmp_msg_version version;
    uint8_t mic[NLMP_HEADER_MIC_DIM];
} nlmp_authenticate_msg_header_t;

/******* Fixed Header for messagges *******/
typedef struct nlmp_header_t {
    uint8_t signature[NLMP_HEADER_SIGNATURE_DIM];
    nlmp_msg_type_t message_type;
    union {
        nlmp_negotiate_msg_header_t nlmp_negotiate_msg_header;
        nlmp_challenge_msg_header_t nlmp_challenge_msg_header;
        nlmp_authenticate_msg_header_t nlmp_authenticate_msg_header;
    } msg_header;
} nlmp_header_t;


/******************************************/
//             Main Msg Struct
/******************************************/
typedef struct nlmp_msg_t{
    nlmp_header_t header;
    nlmp_msg_payload_t payload;
} nlmp_msg_t;

/******************************************/
//             Utils Parser
/******************************************/

nlmp_parser_error check_signature(const uint8_t *signature) {
    if (!signature) return NLMP_PARSER_ERROR_INVALID_ARGS;

    for (size_t i = 0; i < NLMP_HEADER_SIGNATURE_DIM; i++) {
        if (signature[i] != ntml_protocol_sign[i]) return NLMP_PARSER_ERROR_INVALID_SIGNATURE;
    }

    return NLMP_PARSER_OK;
}

nlmp_parser_error check_msg_type(nlmp_msg_type_t type) {
    if (type == CHALLENGE_MESSAGE 
    || type == NEGOTIATE_MESSAGE 
    || type == AUTHENTICATE_MESSAGE) return NLMP_PARSER_OK;

    return NLMP_PARSER_ERROR_INVALID_MSG_TYPE;
}


/* Funzione che legge da un buffer 2 byte in little endian e li slava come un uint16 */
nlmp_parser_error read_u16_le(const uint8_t *buffer, size_t len, uint16_t *out) {
    if (!buffer || !out) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < sizeof(uint16_t)) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;
    
    *out = (uint32_t)*(buffer)
           | ((uint32_t)*(buffer + 1) << 8);

    return NLMP_PARSER_OK;
}

/* Funzione che legge da un buffer 4 byte in little endian e li slava come un uint32 */
nlmp_parser_error read_u32_le(const uint8_t *buffer, size_t len, uint32_t *out) {
    if (!buffer || !out) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < sizeof(uint32_t)) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    *out = (uint32_t)*(buffer)
           | ((uint32_t)*(buffer + 1) << 8)
           | ((uint32_t)*(buffer + 2) << 16)
           | ((uint32_t)*(buffer + 3) << 24);

    return NLMP_PARSER_OK;
}

/******************************************/
//             Parse Functions
/******************************************/

nlmp_parser_error parse_header_signature(const uint8_t *buffer, size_t len, uint8_t *signature) {
    if (!buffer || !signature) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < NLMP_HEADER_SIGNATURE_DIM) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    memcpy(signature, buffer, NLMP_HEADER_SIGNATURE_DIM);

    return NLMP_PARSER_OK;
}

/* Protocol fields are little-endian. len lunghezza residua di buffer.*/
/**
 * Per legegre msg_type, negflags usare read_u32_le()
 */

/**
 * Reads little-endian encoded values and reconstructs them into native integers.
 * 
 * La funzione prende un buffer è la sua lunghezza residua. 
 * Salva 8 bytes nella struttura fornita in input come parametro.
 * Il chiamante dovrà aggiornare un contare al ritorno per refernziare
 * correttamente l'offset del buffer.
 */
nlmp_parser_error parse_header_fields(const uint8_t *buffer, size_t len, header_fields_t *fields) {
    if (!buffer || !fields) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < NLMP_HEADER_FIELDS_STRUCT_DIM) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    memset(fields, 0, sizeof(*fields));

    nlmp_parser_error res;
    size_t offset = 0;

    // Prende i primi due byte in little endian e li salva in ordine corretto in un uint16
    res = read_u16_le(buffer, len, &fields->len);
    if (res < NLMP_PARSER_OK) return res;

    // Prende il terzo e quarto byte e li salva in un uint16.
    offset += 2;
    res = read_u16_le(buffer + offset, len - offset, &fields->max_len);
    if (res < NLMP_PARSER_OK) return res;

    // Salva i restatnti 4 byte in un uint32 nell'ordine corretto.
    offset += 2;
    res = read_u32_le(buffer + offset, len - offset, &fields->buffer_offset);
    if (res < NLMP_PARSER_OK) return res;

    return NLMP_PARSER_OK;
}


nlmp_parser_error nlmp_parse(const uint8_t *buffer, size_t len) {

}


int main() {

    size_t len = 40;
    const uint8_t buffer1[] = {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
                        0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
                        0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f};

    const uint8_t buffer2[] = {0x01, 0x01, 0x08, 0x00, 0x02, 0x01, 0x00, 0x00};

    const uint8_t buffer3[] = {0x02, 0x01, 0x00, 0x00};

    nlmp_msg_t msg;
    memset(&msg, 0, sizeof(nlmp_msg_t));

    printf("%d\n", sizeof(nlmp_msg_type_t));

    nlmp_parser_error res;

    res = parse_header_signature(buffer1, len, msg.header.signature);
    if (res < NLMP_PARSER_OK) {
        printf("Error: 0x%x\n", res);
        return 1;
    }

    res = check_signature(msg.header.signature);
    if (res < NLMP_PARSER_OK) {
        printf("Error: 0x%x\n", res);
        return 1;
    }

    res = parse_header_fields(buffer2, 8, &msg.header.msg_header.nlmp_authenticate_msg_header.domain_name_fields);

    res = parse_header_msg_type(buffer3, 4, &msg.header.message_type);

    printf("---%u\n", msg.header.message_type);
    printf("%u\n", msg.header.msg_header.nlmp_authenticate_msg_header.domain_name_fields.buffer_offset);


    

}


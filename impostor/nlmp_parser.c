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

/* Errori parsing */
#define NTLM_PARSER_OK                          0x00000000
#define NTLM_PARSER_ERROR_INVALID_ARGS          0x80000001
#define NTLM_PARSER_ERROR_INVALID_SIGNATURE     0x80000002
#define NTLM_PARSER_ERROR_INVALID_MSG_TYPE      0x80000003
#define NTLM_PARSER_ERROR_BUFF_OVERFLOW         0x80000004
#define NTLM_PARSER_ERROR_BUFF_TOO_BIG          0x80000005
#define NTLM_PARSER_ERROR_MALFORMED_MSG         0x80000006

typedef int32_t ntlm_parser_error;

/* Costanti utili (dimensioni, limiti)*/
#define NTLM_MAX_MSG_DIM 64 * 1024   // 64 KB

#define NTLM_HEADER_SIGNATURE_SIZE              8     // 8 Bytes
#define NTLM_HEADER_MIC_SIZE                    16    // 16 Bytes

#define NTLM_HEADER_FIELDS_STRUCT_SIZE          8     // 8 Bytes - 64 bit
#define NTLM_NEGOTIATE_MESSAGE_HEADER_SIZE      40    // Signature + MessageType 
                                                      // + NegotiateFlags + DomainNameFields 
                                                      // + WorkstationFields + Version

#define NTLM_V2_RESPONSE_SIZE   16   // 16 Bytes
#define NTLM_RESPONSE_SIZE      24   // 24 Bytes

#define LM_V2_RESPONSE_SIZE   24   // 24 Bytes
#define LM_RESPONSE_SIZE      24   // 24 Bytes

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
//       Structs for Msg's Headers
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


typedef struct ntlm_negotiate_msg_header_t {
    ntlm_negotiate_flags_t negotiate_flags;

    header_fields_t domain_name_fields;
    header_fields_t workstation_fields;

    uint8_t version_present;
    ntlm_blob_t version;
} ntlm_negotiate_msg_header_t;


typedef struct ntlm_challenge_msg_header_t {
    header_fields_t target_name_fields;

    ntlm_negotiate_flags_t negotiate_flags;
    uint64_t server_challenge;

    uint8_t reserved[8];

    header_fields_t target_info_fields;

    uint8_t version_present;
    ntlm_blob_t version;
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
    ntlm_blob_t version;

    uint8_t mic_present;
    uint8_t mic[NTLM_HEADER_MIC_SIZE];
} ntlm_authenticate_msg_header_t;

/******* Fixed Header for messagges *******/
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

// In totlae 24 Bytes
typedef struct lm_v2_response_t {
    uint8_t response[LM_V2_RESPONSE_SIZE];
    uint64_t challenge_from_client;
} lm_v2_response_t;

// In totlae 24 Bytes
typedef struct lm_response_t {
    uint8_t response[LM_RESPONSE_SIZE];
} lm_response_t;

/*************/

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
//          Msg and Buffer Utils 
/******************************************/

ntlm_parser_error free_ntlm_msg(ntlm_msg_t msg) {

}


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

/* Funzione che legge da un buffer 8 byte in little endian e li slava come un uint64 */
nlmp_parser_error read_u64_le(const uint8_t *buffer, size_t len, uint64_t *out) {
    if (!buffer || !out) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < sizeof(uint64_t)) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    *out = (uint64_t)*(buffer)
           | ((uint64_t)*(buffer + 1) << 8)
           | ((uint64_t)*(buffer + 2) << 16)
           | ((uint64_t)*(buffer + 3) << 24)
           | ((uint64_t)*(buffer + 4) << 32)
           | ((uint64_t)*(buffer + 5) << 40)
           | ((uint64_t)*(buffer + 6) << 48)
           | ((uint64_t)*(buffer + 7) << 56);

    return NLMP_PARSER_OK;
}
























/******************************************/
//             Parse Functions
/******************************************/

nlmp_parser_error parse_header_signature(const uint8_t *buffer, size_t len, uint8_t *signature) {
    if (!buffer || !signature) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len < NLMP_HEADER_SIGNATURE_SIZE) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    memcpy(signature, buffer, NLMP_HEADER_SIGNATURE_SIZE);

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

    if (len < NLMP_HEADER_FIELDS_STRUCT_SIZE) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

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

/**
 * Parsa un messaggio NEGOTIATE_MESSAGE.
 */
nlmp_parser_error nlmp_parse_negotiate_message(const uint8_t *buffer, size_t len, size_t *offset, nlmp_msg_t *msg) {
    if (!buffer || !msg || !offset) return NLMP_PARSER_ERROR_INVALID_ARGS;

    nlmp_parser_error res;

    // Dobbiamo leggere dal buffer l'header, quindi verifichiamo che le letture non 
    // siano superiori alla lunghezza del buffer
    if (len < NLMP_NEGOTIATE_MESSAGE_HEADER_SIZE) return NLMP_PARSER_ERROR_BUFF_OVERFLOW;

    // Recuperiamo flags
    res = read_u32_le(buffer + *offset, len, &msg->header.msg_header.nlmp_negotiate_msg_header.negotiate_flags);
    if (res < NLMP_PARSER_OK) return res;
    *offset += sizeof(uint32_t);

    // Recuperiamo campi domain_name_fields
    if (msg->header.msg_header.nlmp_negotiate_msg_header.negotiate_flags & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) {
        res = parse_header_fields(buffer + *offset, len - *offset, &msg->header.msg_header.nlmp_negotiate_msg_header.domain_name_fields);
        if (res < NLMP_PARSER_OK) return res;
    } else {
        msg->header.msg_header.nlmp_negotiate_msg_header.domain_name_fields.buffer_offset = NLMP_NEGOTIATE_MESSAGE_HEADER_SIZE;
    }
    *offset += NLMP_HEADER_SIGNATURE_SIZE;

    // Recuperiamo campi workstation_fields
    if (msg->header.msg_header.nlmp_negotiate_msg_header.negotiate_flags & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) {
        res = parse_header_fields(buffer + *offset, len - *offset, &msg->header.msg_header.nlmp_negotiate_msg_header.workstation_fields);
        if (res < NLMP_PARSER_OK) return res;
    } else {
        msg->header.msg_header.nlmp_negotiate_msg_header.workstation_fields.buffer_offset = NLMP_NEGOTIATE_MESSAGE_HEADER_SIZE;
    }
    *offset += NLMP_HEADER_SIGNATURE_SIZE;

    // Recuperiamo campi version
    if (msg->header.msg_header.nlmp_negotiate_msg_header.negotiate_flags & NTLMSSP_NEGOTIATE_VERSION) {
        res = read_u64_le(buffer + *offset, len - *offset, &msg->header.msg_header.nlmp_negotiate_msg_header.version);
        if (res < NLMP_PARSER_OK) return res;
    } else {
        msg->header.msg_header.nlmp_negotiate_msg_header.version = 0;
    }
    *offset += sizeof(uint64_t);

    // Estraiamo Payload in base alle lunghezze

    // Se offset, dove dovremmo iniziare ad estrarre il payload è uguale alla lunghezza allora non abbiamo payload
    if (*offset >= len) {
        msg->payload = NULL;
        return NLMP_PARSER_OK;
    }

    // Altrimenti calcolsimao lunghezza payload ed estraiamo


    printf("Type: 0x%08x\n", msg->header.message_type);
    printf("Sign: %s\n", msg->header.signature);
    printf("Flags: 0x%08x\n", msg->header.msg_header.nlmp_negotiate_msg_header.negotiate_flags);
    printf("Domain Len: %d, Offset: %d\n", msg->header.msg_header.nlmp_negotiate_msg_header.domain_name_fields.len, msg->header.msg_header.nlmp_negotiate_msg_header.domain_name_fields.buffer_offset);
    printf("Workst. Len: %d, Offset: %d\n", msg->header.msg_header.nlmp_negotiate_msg_header.workstation_fields.len, msg->header.msg_header.nlmp_negotiate_msg_header.workstation_fields.buffer_offset);
    printf("Version: 0x%016llx\n", msg->header.msg_header.nlmp_negotiate_msg_header.version);


}

nlmp_parser_error nlmp_parse_challenge_message(const uint8_t *buffer, size_t len, nlmp_msg_t *msg) {}

nlmp_parser_error nlmp_parse_authenticate_message(const uint8_t *buffer, size_t len, nlmp_msg_t *msg) {}


nlmp_parser_error nlmp_parse(const uint8_t *buffer, size_t len, nlmp_msg_t *msg) {
    if (!buffer || !msg) return NLMP_PARSER_ERROR_INVALID_ARGS;

    if (len > NLMP_MAX_MSG_DIM) return NLMP_PARSER_ERROR_BUFF_TOO_BIG;

    memset(msg, 0, sizeof(nlmp_msg_t));
    
    size_t offset = 0;
    nlmp_parser_error res;

    // Estraggo signature del protocollo
    res = parse_header_signature(buffer, len, msg->header.signature);
    if (res < NLMP_PARSER_OK) return res;
    offset += NLMP_HEADER_SIGNATURE_SIZE;

    // Verifichiamo se la firma è valida
    res = check_signature(msg->header.signature);
    if (res < NLMP_PARSER_OK) return res;

    // Estraggo message type
    res = read_u32_le(buffer + offset, len - offset, &msg->header.message_type);
    if (res < NLMP_PARSER_OK) return NLMP_PARSER_OK;
    offset += sizeof(uint32_t);

    // Verifichaimo se tipo è valido
    res = check_msg_type(msg->header.message_type);
    if (res < NLMP_PARSER_OK) return res;
    
    // In base al tipo, faccimo il parse del messaggio
    switch (msg->header.message_type) {
        case NEGOTIATE_MESSAGE:
            res = nlmp_parse_negotiate_message(buffer, len, &offset, msg);
            if (res < NLMP_PARSER_OK) return res;
            break;

        case CHALLENGE_MESSAGE:
            res = nlmp_parse_challenge_message(buffer + offset, len - offset, msg);
            if (res < NLMP_PARSER_OK) return res;
            break;

        case AUTHENTICATE_MESSAGE:
            res = nlmp_parse_authenticate_message(buffer + offset, len - offset, msg);
            if (res < NLMP_PARSER_OK) return res;
            break;
        
        default:
            return NLMP_PARSER_ERROR_INVALID_MSG_TYPE;
    }

    return NLMP_PARSER_OK;

}


int main() {

    size_t len = 40;
    const uint8_t buffer1[] = {0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
                        0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00,
                        0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f};

    const uint8_t buffer2[] = {0x01, 0x01, 0x08, 0x00, 0x02, 0x01, 0x00, 0x00};

    const uint8_t buffer3[] = {0x02, 0x01, 0x00, 0x00};

    nlmp_msg_t msg;
    nlmp_parser_error res;
    memset(&msg, 0, sizeof(nlmp_msg_t));

    res = nlmp_parse(buffer1, 40, &msg);
    if (res < NLMP_PARSER_OK) {
        printf("Errore: 0x%x\n", res);
        return 1;
    }

    printf("OK.\n");


    

}


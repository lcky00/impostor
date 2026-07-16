/**
 * Parser for NTLM Authentication Protocol
 * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/907f519d-6217-45b1-b421-dca10fc8af0d
 * 
 * Luca Vinci <luca9vinci at gmail dot com>
 * 
 * Parser non zero-copy, crea copia del buffer nella struttura di output.
 * Andarà liberata memoria dal chiamante. Non intacca buffer.
 * 
 * All numeric fields in output are host-endian.
 * 
 */


#include <string.h>

#include <iconv.h>
#include <stdarg.h>

#include "ntlm_parser.h"

/* Firma del protcollo */
static const uint8_t ntlm_protocol_sign[NTLM_HEADER_SIGNATURE_SIZE] = {'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'};

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
    if (!buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

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
void read_u8(const uint8_t *buff, uint8_t *out) {
    *out = ((uint16_t)buff[0]);
}

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
ntlm_parser_error ntlm_ctx_buffer_read_u8(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *out) {
    if (!ctx_buffer || !out) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    if ((res = ntlm_ctx_buffer_is_valid(ctx_buffer)) < NTLM_PARSER_OK) return res;
    // devo leggere dal buffer 1 byte, controlliamo che la lunghezza residue sia almeno di due byte
    if ((res = ntlm_ctx_buffer_check_safe_read(ctx_buffer, sizeof(uint8_t))) < NTLM_PARSER_OK) return res;
    
    size_t offset = ctx_buffer->offset;
    read_u8(ctx_buffer->buf + offset, out);

    if ((res = ntlm_ctx_buff_safe_incr_offset(ctx_buffer, sizeof(uint8_t))) < NTLM_PARSER_OK) return res;
    
    return NTLM_PARSER_OK;
}

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

ntlm_parser_error generic_n_bytes_read(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *dest, size_t len) {
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
    return generic_n_bytes_read(ctx_buffer, mic, NTLM_HEADER_MIC_SIZE);
}

ntlm_parser_error signature_header_parse(ntlm_buffer_ctx_t *ctx_buffer, uint8_t *signature) {
    return generic_n_bytes_read(ctx_buffer, signature, NTLM_HEADER_SIGNATURE_SIZE);
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

/******************************************/
//          Decode Functions
/******************************************/

/********* Parsing per campi payload specifici *********/

void ntlm_av_pairs_free(av_pair_t ***av_pairs, size_t len) {
    if (!av_pairs || !*av_pairs) return;
    for (size_t i = 0; i < len; i++) {
        if ((*av_pairs)[i]) {
            if ((*av_pairs)[i]->value) {
                free((*av_pairs)[i]->value);
                (*av_pairs)[i]->value = NULL;
            }
            free((*av_pairs)[i]);
            (*av_pairs)[i] = NULL;
        }
    }

    free(*av_pairs);
    *av_pairs = NULL;
}

uint8_t check_av_id(av_pair_id_t type) {
    return type == MSV_AV_EOL || type == MSV_AV_NB_COMPUTER_NAME 
            || type == MSV_AV_NB_DOMAIN_NAME || type == MSV_AV_DNS_COMPUTER_NAME 
            || type == MSV_AV_DNS_DOMAIN_NAME || type == MSV_AV_DNS_TREE_NAME 
            || type == MSV_AV_FLAGS || type == MSV_AV_TIMESTAMP 
            || type == MSV_AV_SINGLE_HOST || type == MSV_AV_TARGET_NAME 
            || type == MSV_AV_CHANNEL_BINDINGS;
}

ntlm_parser_error parse_av_pair(ntlm_buffer_ctx_t *ctx_buffer, av_pair_t **av_pair) {
    if (!ctx_buffer || !av_pair) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;

    *av_pair = malloc(sizeof(av_pair_t));
    if (!*av_pair) return NTLM_PARSER_ERROR_ALLOC_AV_PAIR;

    (*av_pair)->value = NULL;

    // Leggiamo AvId, AvLen e Value 
    if ((res = ntlm_ctx_buffer_read_u16_le(ctx_buffer, &(*av_pair)->av_id)) < NTLM_PARSER_OK) {
        free(*av_pair);
        *av_pair = NULL;
        return res;
    }

    if (!check_av_id((*av_pair)->av_id)) {
        free(*av_pair);
        *av_pair = NULL;
        return NTLM_PARSER_ERROR_INVALID_AV_ID;
    }

    if ((res = ntlm_ctx_buffer_read_u16_le(ctx_buffer, &(*av_pair)->av_len)) < NTLM_PARSER_OK) {
        free(*av_pair);
        *av_pair = NULL;
        return res;
    }

    if ((*av_pair)->av_len > ctx_buffer->size) {
        free(*av_pair);
        *av_pair = NULL;
        return NTLM_PARSER_ERROR_LEN_AV_PAIR;
    }

    if ((*av_pair)->av_len == 0) {
        (*av_pair)->value = NULL;
        return NTLM_PARSER_OK;
    }

    (*av_pair)->value = malloc(sizeof(uint8_t) * (*av_pair)->av_len);
    if (!(*av_pair)->value) {
        free(*av_pair);
        *av_pair = NULL;
        return NTLM_PARSER_ERROR_ALLOC_AV_PAIR;
    }

    uint8_t *v = (*av_pair)->value;
    if ((res = generic_n_bytes_read(ctx_buffer, v, (*av_pair)->av_len)) < NTLM_PARSER_OK) {
        free(v);
        free(*av_pair);
        *av_pair = NULL;
        return res;
    }

    return NTLM_PARSER_OK;

}

ntlm_parser_error parse_av_pairs(ntlm_buffer_ctx_t *ctx_buffer, av_pair_t ***av_pairs, size_t *out_size, size_t *out_dim) {
    if (!ctx_buffer || !av_pairs || !out_size || !out_dim) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;
    av_pair_t *av_pair_aux;

    *out_size = 0;
    *out_dim = 1;
    *av_pairs = malloc(sizeof(av_pair_t*) * (*out_dim));
    if (!*av_pairs) return NTLM_PARSER_ERROR_ALLOC_AV_PAIR;

    while(1) {
        if (*out_size >= NTLM_MAX_AV_PAIRS) {
            ntlm_av_pairs_free(av_pairs, *out_size);
            return NTLM_PARSER_ERROR_MAX_AV_PAIR_REACHED;
        }

        if ((res = parse_av_pair(ctx_buffer, &av_pair_aux)) < NTLM_PARSER_OK) {
            ntlm_av_pairs_free(av_pairs, *out_size);
            return res;
        }

        if (av_pair_aux->av_id == MSV_AV_EOL) {
            free(av_pair_aux); 
            break;
        }
        
        if (*out_size >= *out_dim) {
            av_pair_t **tmp = realloc(*av_pairs, sizeof(av_pair_t*) * (*out_dim * 2));
            if (!tmp) {
                free(av_pair_aux);
                ntlm_av_pairs_free(av_pairs, *out_size);
                return NTLM_PARSER_ERROR_ALLOC_AV_PAIR;
            }

            *out_dim = *out_dim * 2;
            *av_pairs = tmp;
        }
        (*av_pairs)[*out_size] = av_pair_aux;
        (*out_size)++;
    }

    return NTLM_PARSER_OK;
}

ntlm_parser_error ntlm_v2_response_payload_parse(ntlm_blob_t *blob, ntlm_v2_response_t *resp) {
    if (!blob || !resp) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (!blob->data) return NTLM_PARSER_ERROR_INVALID_BLOB;

    memset(resp, 0, sizeof(*resp));

    ntlm_parser_error res;
    ntlm_buffer_ctx_t ntlm_v2_buff_ctx;

    ntlm_v2_client_challenge_t *c = &resp->ntlm_v2_client_challenge;
    
    if ((res = ntlm_ctx_buffer_init(blob->data, blob->len, &ntlm_v2_buff_ctx)) < NTLM_PARSER_OK) return res;

    // Leggiamo Response, RespType, HiRespType, Reserved1, Reserved2,
    // TimeStamp, ChallengeFromClient, Reserved3
    if ((res = generic_n_bytes_read(&ntlm_v2_buff_ctx, resp->response, NTLM_V2_RESPONSE_SIZE)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u8(&ntlm_v2_buff_ctx, &c->resp_type)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u8(&ntlm_v2_buff_ctx, &c->hi_resp_type)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u16(&ntlm_v2_buff_ctx, &c->reserved_1)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u32(&ntlm_v2_buff_ctx, &c->reserved_2)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u64(&ntlm_v2_buff_ctx, &c->time_stamp)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u64(&ntlm_v2_buff_ctx, &c->challenge_from_client)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u32(&ntlm_v2_buff_ctx, &c->reserved_3)) < NTLM_PARSER_OK) return res;

    // Leggiamo AvPairs 
    if ((res = parse_av_pairs(&ntlm_v2_buff_ctx, &c->av_pairs, &c->av_pairs_size, &c->av_pairs_dim)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error lm_v2_response_payload_parse(ntlm_blob_t *blob, lm_v2_response_t *resp) {
    if (!blob || !resp) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (!blob->data) return NTLM_PARSER_ERROR_INVALID_BLOB;

    memset(resp, 0, sizeof(*resp));

    ntlm_parser_error res;
    ntlm_buffer_ctx_t lm_v2_buff_ctx;

    if ((res = ntlm_ctx_buffer_init(blob->data, blob->len, &lm_v2_buff_ctx)) < NTLM_PARSER_OK) return res;

    // Leggiamo Response (16 bytes) e ChallengeFromClient
    if ((res = generic_n_bytes_read(&lm_v2_buff_ctx, resp->response, LM_V2_RESPONSE_SIZE)) < NTLM_PARSER_OK) return res;
    if ((res = ntlm_ctx_buffer_read_u64(&lm_v2_buff_ctx, &resp->challenge_from_client)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

ntlm_parser_error target_info_payload_parse(ntlm_blob_t *blob, av_pair_t ***av_pairs, size_t *out_size, size_t *out_dim) {
    if (!blob || !av_pairs || !out_size || !out_dim) return NTLM_PARSER_ERROR_INVALID_ARGS;
    if (!blob->data) return NTLM_PARSER_ERROR_INVALID_BLOB;

    ntlm_parser_error res;
    ntlm_buffer_ctx_t av_pairs_buff_ctx;

    if ((res = ntlm_ctx_buffer_init(blob->data, blob->len, &av_pairs_buff_ctx)) < NTLM_PARSER_OK) return res;
    if ((res = parse_av_pairs(&av_pairs_buff_ctx, av_pairs, out_size, out_dim)) < NTLM_PARSER_OK) return res;

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
    if ((res = check_signature(msg->header.signature)) < NTLM_PARSER_OK) return res;

    if ((res = msg_type_header_parse(ctx_buffer, &msg->header.message_type)) < NTLM_PARSER_OK) return res;
    if ((res = check_msg_type(msg->header.message_type)) < NTLM_PARSER_OK) return res;

    // Parsiamo header e payload
    if ((res = parse_ntlm_msg_header(ctx_buffer, msg)) < NTLM_PARSER_OK) return res;
    if ((res = parse_ntlm_msg_payload(ctx_buffer, msg)) < NTLM_PARSER_OK) return res;

    return NTLM_PARSER_OK;
}

/******************************************/
//           Helper functions
/******************************************/

static ntlm_logger_t logger = NULL;

void set_ntlm_logger(ntlm_logger_t logger_cb) {
    logger = logger_cb;
}

// Funzione di log generica della libreria
void ntlm_log(const char *format, ...) {
    if (logger == NULL) return;

    va_list args;               // lista di argomenti variabili
    va_start(args, format);     // inizializza va_list con l'ultimo parametro noto

    logger(format, args);       // Usa logger utente

    va_end(args);               // libera le risorse di va_list
}

ntlm_parser_error dump_utf16_le_string(const uint8_t *data, size_t len) {
    if (!data || len == 0) return NTLM_PARSER_ERROR_INVALID_ARGS;

    // Prepariamo iconv
    iconv_t cd = iconv_open("UTF-8", "UTF-16LE");
    if (cd == (iconv_t)-1) return NTLM_PARSER_ERROR_CONVERSION;

    size_t inbytesleft = len;
    char *inbuf = (char *)data;

    // buffer di output sufficientemente grande (UTF-8 può usare fino a 4 byte per carattere)
    size_t outlen = len * 2 + 1;  
    char *outbuf = malloc(outlen);
    if (!outbuf) {
        iconv_close(cd);
        return NTLM_PARSER_ERROR_CONVERSION;
    }

    char *outptr = outbuf;
    size_t outbytesleft = outlen;

    // Conversione
    if (iconv(cd, &inbuf, &inbytesleft, &outptr, &outbytesleft) == (size_t)-1) {
        free(outbuf);
        iconv_close(cd);
        return NTLM_PARSER_ERROR_CONVERSION;
    }

    // Stampiamo la stringa convertita
    *outptr = '\0';  // terminatore
    ntlm_log("%s\n", outbuf);

    free(outbuf);
    iconv_close(cd);

    return NTLM_PARSER_OK;
}

ntlm_parser_error dump_header_field(const char *name, const header_fields_t *field) {
    if (!field) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_log("Header Field %s:\n", name);
    ntlm_log("  len: %u\n", field->len);
    ntlm_log("  max_len: %u\n", field->max_len);
    ntlm_log("  buffer_offset: %u\n", field->buffer_offset);

    return NTLM_PARSER_OK;
}

ntlm_parser_error dump_av_pairs(av_pair_t **av_pairs, size_t size) {
    if (!av_pairs) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;

    ntlm_log("AV Pairs [%zu]:\n", size);
    for (size_t i = 0; i < size; i++) {
        if (!av_pairs[i]) continue;
        
        ntlm_log("  AV ID: 0x%04x, Len: %u, Value: ", av_pairs[i]->av_id, av_pairs[i]->av_len);

        if (av_pairs[i]->av_id == MSV_AV_CHANNEL_BINDINGS || 
            av_pairs[i]->av_id == MSV_AV_SINGLE_HOST || 
            av_pairs[i]->av_id == MSV_AV_TIMESTAMP || 
            av_pairs[i]->av_id == MSV_AV_FLAGS) {
            
            for (uint16_t j = 0; j < av_pairs[i]->av_len; j++) {
                ntlm_log("%02x ", av_pairs[i]->value[j]);
            }
            ntlm_log("\n");
        }
        
        else {
            res = dump_utf16_le_string(av_pairs[i]->value, av_pairs[i]->av_len);
            if (res < NTLM_PARSER_OK) return res;

        }
        
    }

    return NTLM_PARSER_OK;
}

ntlm_parser_error dump_msg(ntlm_msg_t *msg) {
    if (!msg) return NTLM_PARSER_ERROR_INVALID_ARGS;

    ntlm_parser_error res;

    ntlm_log("NTLM Message Type: %u\n", msg->header.message_type);

    switch (msg->header.message_type) {
        case NEGOTIATE_MESSAGE:
            dump_header_field("DomainName", &msg->header.msg_header.ntlm_negotiate_msg_header.domain_name_fields);
            dump_header_field("Workstation", &msg->header.msg_header.ntlm_negotiate_msg_header.workstation_fields);
            dump_utf16_le_string(msg->payload.ntlm_negotiate_msg_payload.domain_name.data,
                                 msg->payload.ntlm_negotiate_msg_payload.domain_name.len);
            dump_utf16_le_string(msg->payload.ntlm_negotiate_msg_payload.workstation_name.data,
                                 msg->payload.ntlm_negotiate_msg_payload.workstation_name.len);
            break;

        case CHALLENGE_MESSAGE:
            dump_header_field("TargetName", &msg->header.msg_header.ntlm_challenge_msg_header.target_name_fields);
            dump_header_field("TargetInfo", &msg->header.msg_header.ntlm_challenge_msg_header.target_info_fields);

            av_pair_t **av_pairs;
            size_t outsize, outdim;
            if ((res = target_info_payload_parse(&msg->payload.ntlm_challenge_msg_payload.target_info, &av_pairs, &outsize, &outdim)) < NTLM_PARSER_OK) {
                return res;
            }

            dump_av_pairs(av_pairs, outsize);
            break;

        case AUTHENTICATE_MESSAGE:
            dump_header_field("LmChallengeResponseFields", &msg->header.msg_header.ntlm_authenticate_msg_header.lm_challenge_resp_fields);
            dump_header_field("NtChallengeResponseFields", &msg->header.msg_header.ntlm_authenticate_msg_header.nt_challenge_resp_fields);
            dump_header_field("DomainNameFields", &msg->header.msg_header.ntlm_authenticate_msg_header.domain_name_fields);

            dump_header_field("UserNameFields", &msg->header.msg_header.ntlm_authenticate_msg_header.username_fields);
            dump_header_field("WorkstationFields", &msg->header.msg_header.ntlm_authenticate_msg_header.workstation_fields);
            dump_header_field("EncryptedRandomSessionKeyFields", &msg->header.msg_header.ntlm_authenticate_msg_header.encrypted_random_session_key_fields);
            
            ntlm_log("NtChallengeResponse ");
            
            if (msg->payload.ntlm_authenticate_msg_payload.ntlm_response_type == NTLM_RESPONSE_V2) {
                ntlm_log("(NTLM_V2):\n");
                ntlm_v2_response_t tmp;
                res = ntlm_v2_response_payload_parse(&msg->payload.ntlm_authenticate_msg_payload.nt_challenge_response, &tmp);
                if (res < NTLM_PARSER_OK) return res;
                res = dump_av_pairs(tmp.ntlm_v2_client_challenge.av_pairs, tmp.ntlm_v2_client_challenge.av_pairs_size);
                if (res < NTLM_PARSER_OK) return res;
                ntlm_av_pairs_free(&tmp.ntlm_v2_client_challenge.av_pairs, tmp.ntlm_v2_client_challenge.av_pairs_size);
            }

            ntlm_log("DomainName: ");
            dump_utf16_le_string(msg->payload.ntlm_authenticate_msg_payload.domain_name.data, msg->payload.ntlm_authenticate_msg_payload.domain_name.len);

            ntlm_log("UserName: ");
            dump_utf16_le_string(msg->payload.ntlm_authenticate_msg_payload.username.data, msg->payload.ntlm_authenticate_msg_payload.username.len);

            ntlm_log("Workstation: ");
            dump_utf16_le_string(msg->payload.ntlm_authenticate_msg_payload.workstation_name.data, msg->payload.ntlm_authenticate_msg_payload.workstation_name.len);

            break;

        default:
            ntlm_log("Unknown NTLM message type\n");
            return NTLM_PARSER_ERROR_INVALID_MSG_TYPE;
    }

    return NTLM_PARSER_OK;
}

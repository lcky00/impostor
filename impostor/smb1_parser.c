#include "smb1_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Unset system's macro to use mine */
#undef htobe16
#undef htole16
#undef htobe32
#undef htole32
#undef htobe64
#undef htole64

#include "endianness.h"

#define IS_RESPONSE(flags) (((flags) & SMB_FLAGS_REPLY) != 0)
#define IS_UNICODE(flags2) (((flags2) & SMB_FLAGS2_UNICODE) != 0)
#define IS_EVEN(n) (((n) % 2) == 0)

#define SMB_HEADER_SIZE 32

// SMB Signature
const uint8_t smb_sign[4] = {0xff, 0x53, 0x4d, 0x42};

// SMB Commands
typedef struct {
    uint8_t cmd;
    char *name;
} smb_cmd_t;

const smb_cmd_t commands[] = {
    {SMB_COM_NEGOTIATE, "SMB_COM_NEGOTIATE"},
    {SMB_COM_SESSION_SETUP_ANDX, "SMB_COM_SESSION_SETUP_ANDX"},
};


static int is_valid_smb_command(uint8_t command) {
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (commands[i].cmd == command)
            return 1;
    }
    return 0;
}

static int ctx_msg_safe_read(const ctx_msg_t *ctx_msg, size_t n) {
    return n > 0 
            && ctx_msg->offset <= ctx_msg->len 
            && n <= ctx_msg->len - ctx_msg->offset;
}

static int ctx_safe_extract(ctx_msg_t *ctx_msg, size_t n, uint8_t *out, size_t out_dim) {
    if (!ctx_msg_safe_read(ctx_msg, n) 
        || n != out_dim
        || n == 0) return 0;

    memcpy(out, ctx_msg->msg + ctx_msg->offset, n);

    ctx_msg->offset += n;
    return 1;
}

static int ctx_safe_extract_smb_string(ctx_msg_t *ctx_msg, uint8_t **out_string, size_t *out_dim, int unicode) {
    *out_string = NULL;
    *out_dim = 0;

    size_t old_offset = ctx_msg->offset;
    int found_terminator = 0;
    int allign = 0;

    if (unicode) {
        
        // Check for padding
        if (!IS_EVEN(ctx_msg->base_offset + ctx_msg->offset)) {
            if (!ctx_msg_safe_read(ctx_msg, 1))
                return 0;
            ctx_msg->offset++;
            allign = 1;
        }

        old_offset = ctx_msg->offset;

        // Safety check and find string length
        while (ctx_msg_safe_read(ctx_msg, 1)) {
            *out_dim += 1;
            ctx_msg->offset += 1;

            if (ctx_msg_safe_read(ctx_msg, 1)) {

                ctx_msg->offset += 1;
                *out_dim += 1;
                
                if (ctx_msg->msg[ctx_msg->offset - 2] == 0x00 
                    && ctx_msg->msg[ctx_msg->offset - 1] == 0x00) {
                        found_terminator = 1;
                        break;
                }
                continue;
            }

            // restoring old offset and quit
            ctx_msg->offset = old_offset - allign;
            return 0;
        }

        if (!found_terminator) {
            ctx_msg->offset = old_offset - allign;
            return 0;
        }

        // If it's empty, I don't waste time and space.
        if (*out_dim == 2) {
            *out_string = NULL;
            *out_dim = 0;
            return 1;
        }
    } 

    else {
        while (ctx_msg_safe_read(ctx_msg, 1)) {
            *out_dim += 1;
            ctx_msg->offset += 1; 
            if (ctx_msg->msg[ctx_msg->offset - 1] == 0x00) {
                found_terminator = 1;
                break;
            }          
        }

        if (!found_terminator) {
            ctx_msg->offset = old_offset;
            return 0;
        }

        if (*out_dim == 1) {
            *out_string = NULL;
            *out_dim = 0;
            return 1;
        }
    }

    // Copy string
    *out_string = calloc(*out_dim, sizeof(uint8_t));
    if (!*out_string) {
        ctx_msg->offset = old_offset - allign;
        *out_dim = 0;
        return 0;
    }

    memcpy(*out_string, ctx_msg->msg + old_offset, *out_dim);

    return 1;
}


/******************/

static smb_parser_error_t smb_parse_header(ctx_msg_t *ctx_msg, smb_raw_msg_t *raw_smb_parsed) {
    // Parse Protocol Sign
    if (!ctx_safe_extract(ctx_msg, sizeof(smb_sign), 
                         raw_smb_parsed->header.protocol, 
                         sizeof(raw_smb_parsed->header.protocol))) return SMB_PARSER_ERR_EXTRACT;

    if (memcmp(raw_smb_parsed->header.protocol, smb_sign, sizeof(smb_sign)) != 0)
        return SMB_PARSER_ERR_SMB_SIGN;

    // Parse Command
    if (!ctx_safe_extract(ctx_msg, sizeof(uint8_t),
                        &raw_smb_parsed->header.command,
                        sizeof(uint8_t))) return SMB_PARSER_ERR_EXTRACT;

    if (!is_valid_smb_command(raw_smb_parsed->header.command)) return SMB_PARSER_ERR_INVALID_CMD;

    // Parse Status
    if (!ctx_safe_extract(ctx_msg, sizeof(raw_smb_parsed->header.status),
                        raw_smb_parsed->header.status,
                        sizeof(raw_smb_parsed->header.status))) return SMB_PARSER_ERR_EXTRACT;

    // Parse Flag
    if (!ctx_safe_extract(ctx_msg, sizeof(uint8_t),
                        &raw_smb_parsed->header.flags,
                        sizeof(uint8_t))) return SMB_PARSER_ERR_EXTRACT;
    
    // Parse Flag2
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.flags2),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;
    
    raw_smb_parsed->header.flags2 = letoh16(raw_smb_parsed->header.flags2);

    // Parse PidHigh
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.pid_high),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    raw_smb_parsed->header.pid_high = letoh16(raw_smb_parsed->header.pid_high);

    // Parse SecurityFeatures
    if (!ctx_safe_extract(ctx_msg, sizeof(raw_smb_parsed->header.security_features),
                        raw_smb_parsed->header.security_features,
                        sizeof(raw_smb_parsed->header.security_features))) return SMB_PARSER_ERR_EXTRACT;                    

    // Parse Reserved
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.reserved),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    // Parse TID
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.tid),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    raw_smb_parsed->header.tid = letoh16(raw_smb_parsed->header.tid);

    // Parse PIDLow
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.pid_low),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    raw_smb_parsed->header.pid_low = letoh16(raw_smb_parsed->header.pid_low);

    // Parse UID
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.uid),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;
    
    raw_smb_parsed->header.uid = letoh16(raw_smb_parsed->header.uid);

    // Parse MID
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->header.mid),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    raw_smb_parsed->header.mid = letoh16(raw_smb_parsed->header.mid);
    
    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_parameters(ctx_msg_t *ctx_msg, smb_raw_msg_t *raw_smb_parsed) {

    if (ctx_msg->offset == ctx_msg->len) return SMB_PARSER_ERR_MISSING_SMB_PARAMS;

    // Parsing WordCount
    if (!ctx_safe_extract(ctx_msg, sizeof(uint8_t),
                        &raw_smb_parsed->params.word_count,
                        sizeof(uint8_t))) return SMB_PARSER_ERR_EXTRACT;

    size_t bytes = raw_smb_parsed->params.word_count * 2;

    if (bytes == 0) {
        raw_smb_parsed->params.words = NULL;
        return SMB_PARSER_OK;
    }

    uint8_t *words = calloc(bytes, sizeof(uint8_t));
    if (!words) return SMB_PARSER_ERR_ALLOC;

    // Parsing Words
    if (!ctx_safe_extract(ctx_msg, bytes, words, bytes)) {
        free(words);
        return SMB_PARSER_ERR_EXTRACT;
    }

    raw_smb_parsed->params.words = words;

    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_data(ctx_msg_t *ctx_msg, smb_raw_msg_t *raw_smb_parsed) {

    if (ctx_msg->offset == ctx_msg->len) return SMB_PARSER_ERR_MISSING_SMB_DATA;

    // Parsing BytesCount
    if (!ctx_safe_extract(ctx_msg, sizeof(uint16_t),
                        (uint8_t*)(&raw_smb_parsed->data.byte_count),
                        sizeof(uint16_t))) return SMB_PARSER_ERR_EXTRACT;

    raw_smb_parsed->data.byte_count = letoh16(raw_smb_parsed->data.byte_count);

    uint16_t bytes_count = raw_smb_parsed->data.byte_count;

    if (bytes_count == 0) {
        raw_smb_parsed->data.bytes = NULL;
        return SMB_PARSER_OK;
    }

    // Check safety of Bytes
    if (!ctx_msg_safe_read(ctx_msg, bytes_count)) return SMB_PARSER_ERR_UNSAFE_LEN;

    uint8_t *bytes = calloc(bytes_count, sizeof(uint8_t));
    if (!bytes) return SMB_PARSER_ERR_ALLOC;

    // Parsing Bytes
    if (!ctx_safe_extract(ctx_msg, bytes_count, bytes, bytes_count)) {
        free(bytes);
        return SMB_PARSER_ERR_EXTRACT;
    }

    raw_smb_parsed->data.bytes = bytes;

    return SMB_PARSER_OK;
}

smb_parser_error_t smb_parse_msg(uint8_t *msg, size_t len, smb_raw_msg_t *parsed_msg) {
    if (!msg || !parsed_msg || len == 0) return SMB_PARSER_ERR_NULL_ARG;

    smb_parser_error_t res;
    smb_raw_msg_t raw_smb_parsed;

    // Create ctx_msg 
    ctx_msg_t ctx_msg;
    ctx_msg.msg = msg;
    ctx_msg.len = len;
    ctx_msg.offset = 0;
    ctx_msg.base_offset = 0;

    // Parsing Header
    res = smb_parse_header(&ctx_msg, &raw_smb_parsed);
    if (res < SMB_PARSER_OK) return res;

    // Parsing Parameters
    res = smb_parse_parameters(&ctx_msg, &raw_smb_parsed);
    if (res < SMB_PARSER_OK) return res;

    // Parsing Data
    res = smb_parse_data(&ctx_msg, &raw_smb_parsed);
    if (res < SMB_PARSER_OK) {
        free(raw_smb_parsed.params.words);
        return res;
    }

    // If remains bytes to parse -> malformed packet
    if (ctx_msg.len != ctx_msg.offset) {
        free(raw_smb_parsed.params.words);
        free(raw_smb_parsed.data.bytes);
        return SMB_PARSER_ERR_MALFORMED_SMB_MSG;
    }

    *parsed_msg = raw_smb_parsed;
    return SMB_PARSER_OK;
}

void free_smb_raw_msg(smb_raw_msg_t *msg) {
    if (!msg) return;
 
    free(msg->params.words);
    msg->params.words = NULL;
 
    free(msg->data.bytes);
    msg->data.bytes = NULL;
}


/*************************************************/
/*                 SMB PARSE CMD                 */
/*************************************************/

static smb_dialect *parse_dialects(const uint8_t *bytes, size_t len, size_t *out_dim) {
    size_t strings = 0, cont = 0;

    // Validate bytes[]
    while (cont < len) {
        // First byte MUST be 0x02. Indicate that si a NULL-term string
        if (bytes[cont++] != 0x02) return NULL;

        while (cont < len && bytes[cont] != 0x00) {
            cont++;
        }

        if (cont >= len || bytes[cont] != 0x00) return NULL;

        strings++;
        cont++;
    }

    if (strings == 0) return NULL;

    smb_dialect *dialects = calloc(strings, sizeof(smb_dialect));
    if (!dialects) return NULL;

    size_t idx = 0, i = 0;

    while (i < len) {
        dialects[idx].buffer_format = bytes[i++];

        size_t dim = strlen((const char *)(bytes + i)) + 1;
        dialects[idx].dialect_string = calloc(dim, sizeof(uint8_t));
        if (!dialects[idx].dialect_string)
            goto _dialects_err;
        
        memcpy(dialects[idx].dialect_string, bytes + i, dim);
        i += dim;

        idx++;
    }

    *out_dim = strings;
    return dialects;

_dialects_err:
    for (size_t j = 0; j < idx; j++) {
        free(dialects[j].dialect_string);
    }
    free(dialects);
    return NULL;
}

static smb_parser_error_t smb_parse_cmd_0x72_req(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_com_negotiate_req_t *req = &parsed_msg->command.negotiate.req;
    
    // Parse Params
    req->data.dialects = NULL;
    req->params.null = 0;

    if (raw_msg.params.word_count != 0x00) return SMB_PARSER_ERR_0x72_PARSING;

    // Parse Data
    req->data.byte_count = raw_msg.data.byte_count;
    if (req->data.byte_count < 0x2) return SMB_PARSER_ERR_0x72_PARSING;

    // Parsing dialects. NULL-term strings
    req->data.dialects = parse_dialects(raw_msg.data.bytes, req->data.byte_count, &req->data.len);
    if (!req->data.dialects) {
        req->data.len = 0;
        return SMB_PARSER_ERR_0x72_PARSING;
    }

    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_cmd_0x72_res(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_com_negotiate_res_t *res = &parsed_msg->command.negotiate.res;

    res->data.security_blob = NULL;
    res->data.len = 0;

    // Parse Params
    if (raw_msg.params.word_count != 0x11) return SMB_PARSER_ERR_0x72_PARSING;
    
    ctx_msg_t ctx_msg;
    ctx_msg.msg = raw_msg.params.words;
    ctx_msg.len = raw_msg.params.word_count * 2;
    ctx_msg.offset = 0;
    ctx_msg.base_offset = SMB_HEADER_SIZE + 1;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.dialect_index),
                        (uint8_t*)(&res->params.dialect_index),
                        sizeof(res->params.dialect_index))) return SMB_PARSER_ERR_0x72_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.security_mode),
                        (uint8_t*)(&res->params.security_mode),
                        sizeof(res->params.security_mode))) return SMB_PARSER_ERR_0x72_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.max_mpx_count),
                        (uint8_t*)(&res->params.max_mpx_count),
                        sizeof(res->params.max_mpx_count))) return SMB_PARSER_ERR_0x72_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.max_number_vcs),
                        (uint8_t*)(&res->params.max_number_vcs),
                        sizeof(res->params.max_number_vcs))) return SMB_PARSER_ERR_0x72_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.max_buffer_size),
                        (uint8_t*)(&res->params.max_buffer_size),
                        sizeof(res->params.max_buffer_size))) return SMB_PARSER_ERR_0x72_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.max_raw_size),
                        (uint8_t*)(&res->params.max_raw_size),
                        sizeof(res->params.max_raw_size))) return SMB_PARSER_ERR_0x72_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.session_key),
                        (uint8_t*)(&res->params.session_key),
                        sizeof(res->params.session_key))) return SMB_PARSER_ERR_0x72_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.capabilities),
                        (uint8_t*)(&res->params.capabilities),
                        sizeof(res->params.capabilities))) return SMB_PARSER_ERR_0x72_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.system_time),
                        (uint8_t*)(&res->params.system_time),
                        sizeof(res->params.system_time))) return SMB_PARSER_ERR_0x72_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.server_time_zone),
                        (uint8_t*)(&res->params.server_time_zone),
                        sizeof(res->params.server_time_zone))) return SMB_PARSER_ERR_0x72_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.challenge_length),
                        (uint8_t*)(&res->params.challenge_length),
                        sizeof(res->params.challenge_length))) return SMB_PARSER_ERR_0x72_PARSING;
    
    // Handle endianness
    res->params.dialect_index = letoh16(res->params.dialect_index);
    res->params.max_mpx_count = letoh16(res->params.max_mpx_count);
    res->params.max_number_vcs = letoh16(res->params.max_number_vcs);
    res->params.max_buffer_size = letoh32(res->params.max_buffer_size);
    res->params.max_raw_size = letoh32(res->params.max_raw_size);
    res->params.session_key = letoh32(res->params.session_key);
    res->params.capabilities = letoh32(res->params.capabilities);
    res->params.system_time = letoh64(res->params.system_time);
    res->params.server_time_zone = letoh16(res->params.server_time_zone);

    // Parse Data
    if (raw_msg.data.byte_count < 0x10) return SMB_PARSER_ERR_0x72_PARSING;

    res->data.len = raw_msg.data.byte_count - sizeof(res->data.server_guid);
    memcpy(res->data.server_guid, raw_msg.data.bytes, sizeof(res->data.server_guid));
    
    if (res->data.len == 0) {
        res->data.security_blob = NULL;
        return SMB_PARSER_OK;
    }

    res->data.security_blob = calloc(res->data.len, sizeof(uint8_t));
    if (!res->data.security_blob) return SMB_PARSER_ERR_0x72_PARSING;

    memcpy(res->data.security_blob, raw_msg.data.bytes + sizeof(res->data.server_guid), res->data.len);

    return SMB_PARSER_OK;    
}

static smb_parser_error_t smb_parse_cmd_0x72(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_parser_error_t res;

    // The msg is a Response
    if (IS_RESPONSE(parsed_msg->header.flags)) {
        res = smb_parse_cmd_0x72_res(raw_msg, parsed_msg);
        if (res < SMB_PARSER_OK) {
            return res;
        }
    } 
    // The msg is a Request
    else {
        res = smb_parse_cmd_0x72_req(raw_msg, parsed_msg);
        if (res < SMB_PARSER_OK) {
            return res;
        }
    }

    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_cmd_0x73_res(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_com_session_setup_andx_res_t *res = &parsed_msg->command.session_setup_andx.res;

    res->data.security_blob = NULL;
    res->data.native_os = NULL;
    res->data.native_os_len = 0;
    res->data.native_lan_man = NULL;
    res->data.native_lan_man_len = 0;

    if (raw_msg.params.word_count != 0x04) return SMB_PARSER_ERR_0x73_PARSING;

    ctx_msg_t ctx_msg;
    ctx_msg.len = raw_msg.params.word_count * 2;
    ctx_msg.msg = raw_msg.params.words;
    ctx_msg.offset = 0;
    ctx_msg.base_offset = SMB_HEADER_SIZE + 1;

    // Parse Parmas
    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.and_x_command),
                        &res->params.and_x_command,
                        sizeof(res->params.and_x_command))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.and_x_reserved),
                        &res->params.and_x_reserved,
                        sizeof(res->params.and_x_reserved))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.and_x_offset),
                        (uint8_t*)(&res->params.and_x_offset),
                        sizeof(res->params.and_x_offset))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.action),
                        (uint8_t*)(&res->params.action),
                        sizeof(res->params.action))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(res->params.security_blob_len),
                        (uint8_t*)(&res->params.security_blob_len),
                        sizeof(res->params.security_blob_len))) return SMB_PARSER_ERR_0x73_PARSING;

    // Handle Endianness
    res->params.and_x_offset = letoh16(res->params.and_x_offset);
    res->params.action = letoh16(res->params.action);
    res->params.security_blob_len = letoh16(res->params.security_blob_len);

    // Parse Data
    ctx_msg.msg = raw_msg.data.bytes;
    ctx_msg.len = raw_msg.data.byte_count;
    ctx_msg.offset = 0; // Starting from scratch with data
    ctx_msg.base_offset = SMB_HEADER_SIZE + 1 + (raw_msg.params.word_count * 2) + 2;

    uint16_t len = res->params.security_blob_len;

    if (len == 0) {
        res->data.security_blob = NULL;
    }
    else {
        res->data.security_blob = calloc(len, sizeof(uint8_t));
        if (!res->data.security_blob) return SMB_PARSER_ERR_0x73_PARSING;

        if (!ctx_safe_extract(&ctx_msg, len, res->data.security_blob, len)) {
            free(res->data.security_blob);
            res->data.security_blob = NULL;
            return SMB_PARSER_ERR_0x73_PARSING;
        }
    }

    int unicode = IS_UNICODE(raw_msg.header.flags2);

    if (!ctx_safe_extract_smb_string(&ctx_msg, &res->data.native_os, &res->data.native_os_len, unicode)) {
        free(res->data.security_blob);
        res->data.security_blob = NULL;
        return SMB_PARSER_ERR_0x73_PARSING;
    }

    if (!ctx_safe_extract_smb_string(&ctx_msg, &res->data.native_lan_man, &res->data.native_lan_man_len, unicode)) {
        free(res->data.native_os);
        free(res->data.security_blob);
        res->data.native_os = NULL;
        res->data.security_blob = NULL;
        return SMB_PARSER_ERR_0x73_PARSING;
    }

    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_cmd_0x73_req(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_com_session_setup_andx_req_t *req = &parsed_msg->command.session_setup_andx.req;

    req->data.security_blob = NULL;
    req->data.native_os = NULL;
    req->data.native_os_len = 0;
    req->data.native_lan_man = NULL;
    req->data.native_lan_man_len = 0;

    if (raw_msg.params.word_count != 0x0C) return SMB_PARSER_ERR_0x73_PARSING;

    ctx_msg_t ctx_msg;
    ctx_msg.len = raw_msg.params.word_count * 2;
    ctx_msg.msg = raw_msg.params.words;
    ctx_msg.offset = 0;
    ctx_msg.base_offset = SMB_HEADER_SIZE + 1;

    // Parse Parmas
    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.and_x_command),
                        &req->params.and_x_command,
                        sizeof(req->params.and_x_command))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.and_x_reserved),
                        &req->params.and_x_reserved,
                        sizeof(req->params.and_x_reserved))) return SMB_PARSER_ERR_0x73_PARSING;
    
    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.and_x_offset),
                        (uint8_t*)(&req->params.and_x_offset),
                        sizeof(req->params.and_x_offset))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.max_buffer_size),
                        (uint8_t*)(&req->params.max_buffer_size),
                        sizeof(req->params.max_buffer_size))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.max_mpx_count),
                        (uint8_t*)(&req->params.max_mpx_count),
                        sizeof(req->params.max_mpx_count))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.vc_number),
                        (uint8_t*)(&req->params.vc_number),
                        sizeof(req->params.vc_number))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.session_key),
                        (uint8_t*)(&req->params.session_key),
                        sizeof(req->params.session_key))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.security_blob_len),
                        (uint8_t*)(&req->params.security_blob_len),
                        sizeof(req->params.security_blob_len))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.reserved),
                        (uint8_t*)(&req->params.reserved),
                        sizeof(req->params.reserved))) return SMB_PARSER_ERR_0x73_PARSING;

    if (!ctx_safe_extract(&ctx_msg, sizeof(req->params.capabilities),
                        (uint8_t*)(&req->params.capabilities),
                        sizeof(req->params.capabilities))) return SMB_PARSER_ERR_0x73_PARSING;

    // Handel Endianness
    req->params.and_x_offset = letoh16(req->params.and_x_offset);
    req->params.max_buffer_size = letoh16(req->params.max_buffer_size);
    req->params.max_mpx_count = letoh16(req->params.max_mpx_count);
    req->params.vc_number = letoh16(req->params.vc_number);
    req->params.session_key = letoh32(req->params.session_key);
    req->params.security_blob_len = letoh16(req->params.security_blob_len);
    req->params.reserved = letoh32(req->params.reserved);
    req->params.capabilities = letoh32(req->params.capabilities);

    // Parse Data
    ctx_msg.msg = raw_msg.data.bytes;
    ctx_msg.len = raw_msg.data.byte_count;
    ctx_msg.offset = 0; // Starting from scratch with data
    ctx_msg.base_offset = SMB_HEADER_SIZE + 1 + (raw_msg.params.word_count * 2) + 2;

    uint16_t len = req->params.security_blob_len;

    if (len == 0) {
        req->data.security_blob = NULL;
    }
    else {
        req->data.security_blob = calloc(len, sizeof(uint8_t));
        if (!req->data.security_blob) return SMB_PARSER_ERR_0x73_PARSING;

        if (!ctx_safe_extract(&ctx_msg, len, req->data.security_blob, len)) {
            free(req->data.security_blob);
            req->data.security_blob = NULL;
            return SMB_PARSER_ERR_0x73_PARSING;
        }
    }

    int unicode = IS_UNICODE(raw_msg.header.flags2);

    if (!ctx_safe_extract_smb_string(&ctx_msg, &req->data.native_os, &req->data.native_os_len, unicode)) {
        free(req->data.security_blob);
        req->data.security_blob = NULL;
        return SMB_PARSER_ERR_0x73_PARSING;
    }

    if (!ctx_safe_extract_smb_string(&ctx_msg, &req->data.native_lan_man, &req->data.native_lan_man_len, unicode)) {
        free(req->data.native_os);
        free(req->data.security_blob);
        req->data.native_os = NULL;
        req->data.security_blob = NULL;
        return SMB_PARSER_ERR_0x73_PARSING;
    }

    return SMB_PARSER_OK;
}

static smb_parser_error_t smb_parse_cmd_0x73(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    smb_parser_error_t res;

    // The message is a Request
    if (IS_RESPONSE(parsed_msg->header.flags)) {
        res = smb_parse_cmd_0x73_res(raw_msg, parsed_msg);
        if (res < SMB_PARSER_OK) {
            return res;
        }
    }
    // The msg is a Response
    else {
        res = smb_parse_cmd_0x73_req(raw_msg, parsed_msg);
        if (res < SMB_PARSER_OK) {
            return res;
        }
    }

    return SMB_PARSER_OK;
}

smb_parser_error_t smb_parse_cmd(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg) {
    if (!parsed_msg) return SMB_PARSER_ERR_NULL_ARG;

    smb_parser_error_t res;
    parsed_msg->header = raw_msg.header;

    switch (parsed_msg->header.command) {
        case SMB_COM_NEGOTIATE: // Cmd 0x72
            res = smb_parse_cmd_0x72(raw_msg, parsed_msg);
            if (res < SMB_PARSER_OK) 
                return res;
            break;

        case SMB_COM_SESSION_SETUP_ANDX: // Cmd 0x73
            res = smb_parse_cmd_0x73(raw_msg, parsed_msg);
            if (res < SMB_PARSER_OK) 
                return res;
            break;
        
        default:
            return SMB_PARSER_ERR_INVALID_CMD;
    }

    return SMB_PARSER_OK;
}

void free_smb_cmd_msg(smb_parsed_msg_t *msg) {
    if (!msg) return;

    switch (msg->header.command) {
        case SMB_COM_NEGOTIATE:
            // RESPONSE
            if (IS_RESPONSE(msg->header.flags)) {
                free(msg->command.negotiate.res.data.security_blob);
                msg->command.negotiate.res.data.security_blob = NULL;
            }
            // REQUEST
            else {
                if (msg->command.negotiate.req.data.dialects) {
                    for (size_t i = 0; i < msg->command.negotiate.req.data.len; i++) {
                        free(msg->command.negotiate.req.data.dialects[i].dialect_string);
                    }
                    free(msg->command.negotiate.req.data.dialects);
                    msg->command.negotiate.req.data.dialects = NULL;
                }
            }
            break;

        case SMB_COM_SESSION_SETUP_ANDX: {
            data_smb_com_session_setup_andx_t *data = IS_RESPONSE(msg->header.flags)
                ? &msg->command.session_setup_andx.res.data
                : &msg->command.session_setup_andx.req.data;

            free(data->security_blob);
            free(data->native_os);
            free(data->native_lan_man);

            data->security_blob = NULL;
            data->native_os = NULL;
            data->native_lan_man = NULL;
            break;
        }
        default:
            break;
    }
}

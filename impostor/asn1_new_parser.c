#include "asn1_new_parser.h"

#include <string.h>

#define ASN1_NODE_INIT_ALLOC_CHILD 10

/**************************************************/
//                Parser Utils
/**************************************************/

asn1_parser_error_t ctx_buffer_new(uint8_t *data, size_t dim, ctx_buffer_t *out) {
    if (!out || !data) return ERROR_INVALID_ARGS;
    
    out->dim = dim;
    out->data = data;

    return PARSER_OK;
}


uint8_t ctx_buffer_is_safe_offset(ctx_buffer_t buffer, size_t offset) {
    return buffer.dim > 0 && offset <= buffer.dim - 1;
}

uint8_t ctx_buffer_is_safe_len(ctx_buffer_t buffer, size_t offset, size_t len) {
    return ctx_buffer_is_safe_offset(buffer, offset)
            && buffer.dim - offset >= len; // NO "-1" because we also count che offset itself
}

asn1_parser_error_t ctx_buffer_read(ctx_buffer_t buffer, size_t start_offset, size_t bytes_to_read, uint8_t **out) {
    // Check for read safety
    if (!out) return ERROR_INVALID_ARGS;
    
    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;

    if (!ctx_buffer_is_safe_len(buffer, start_offset, bytes_to_read)) 
        return ERROR_UNSAFE_LEN;

    *out = calloc(bytes_to_read, sizeof(uint8_t));
    if (!*out) return ERROR_ALLOCATION;

    memcpy(*out, buffer.data[start_offset], bytes_to_read);

    return PARSER_OK;
}


asn1_parser_error_t tlv_extract_len(ctx_buffer_t buffer, size_t offset, uint8_t *num_bytes, uint64_t *len) {
    if (!num_bytes || !len) return ERROR_INVALID_ARGS;

    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;

    // Safe read the len byte
    uint8_t l_byte;
    if (!ctx_buffer_is_safe_len(buffer, offset, sizeof(l_byte))) 
        return ERROR_UNSAFE_LEN;
    l_byte = buffer.data[offset];

    // Check the Len form
    uint8_t form = (l_byte & 0x80);

    // Long-form
    if (form != 0) {
        *num_bytes = (l_byte & 0x7F);

        if (*num_bytes > PARSER_MAX_NUM_BYTES_FOR_LEN) 
            return ERROR_PARSER_MAX_NUM_BYTES_FOR_LEN;

        // Read the effective len
        offset++;
        if (!ctx_buffer_is_safe_len(buffer, offset, *num_bytes)) 
            return ERROR_UNSAFE_LEN;
        
        *len = 0;

        uint8_t cpy_num_bytes = *num_bytes;
        while (cpy_num_bytes > 0) {
            uint64_t b = buffer.data[offset++];
            *len = (*len << 8) | b;
            cpy_num_bytes--;
        }
        *num_bytes++; // Add Tag Byte

    }
    // Short-form
    else {
        *num_bytes = 1;
        *len = (l_byte & 0x7F);
    }

    if (!ctx_buffer_is_safe_len(buffer, offset, *len)) 
        return ERROR_UNSAFE_LEN;

    return PARSER_OK;
}


asn1_parser_error_t tlv_read_from_buffer(ctx_buffer_t buffer, size_t start_offset, tlv_t *tlv_out) {
    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;
    
    if (!tlv_out) return ERROR_INVALID_ARGS;

    size_t offset = start_offset;

    // Check safety of offset
    if (!ctx_buffer_is_safe_offset(buffer, offset)) 
        return ERROR_UNSAFE_BUFFER_OFFSET;

    // Safe read tag
    asn1_tag_t tag;
    if (!ctx_buffer_is_safe_len(buffer, offset, sizeof(tag))) 
        return ERROR_UNSAFE_LEN;
    
    tag = buffer.data[offset++];

    // Safe extract len info
    size_t tag_value_len, tag_value_len_bytes;
    asn1_parser_error_t res;
    if ((res = tlv_extract_len(buffer, offset, &tag_value_len_bytes, &tag_value_len)) < PARSER_OK) 
        return res;

    offset += tag_value_len_bytes;

    // Prepare the tlv obj to return
    tlv_out->offset_start = start_offset;
    tlv_out->tag = tag;
    tlv_out->tag_value_len = tag_value_len;
    tlv_out->tag_value_len_bytes = tag_value_len_bytes;
    tlv_out->offset_data = offset;

    return PARSER_OK;
}

static asn1_parser_error_t asn1_node_realloc_childs(asn1_node_t *out) {
    if (!out) return ERROR_INVALID_ARGS;

    // Checks if there is somethigs to reallocate
    if (!out->child_nodes) return ERROR_NOTHING_TO_REALLOC;

    asn1_node_t **new_ptr = realloc(out->child_nodes, sizeof(asn1_node_t *) * (out->dim * 2));
    if (!new_ptr) return ERROR_REALLOC;

    out->child_nodes = new_ptr;

    memset(out-> child_nodes + out->dim, 0, out->dim * sizeof(asn1_node_t *));

    out->dim *= 2;

    return PARSER_OK;
}

static asn1_parser_error_t asn1_node_alloc_childs(asn1_node_t *out) {
    if (!out) return ERROR_INVALID_ARGS;

    // check if is already allocated
    if (out->child_nodes) return ERROR_DATA_ALREADY_ALLOC;

    out->child_nodes = calloc(ASN1_NODE_INIT_ALLOC_CHILD, sizeof(asn1_node_t *));
    if (!out->child_nodes) return ERROR_ALLOCATION;

    out->dim = ASN1_NODE_INIT_ALLOC_CHILD;
    out->size = 0;

    return PARSER_OK;
}

asn1_parser_error_t asn1_node_new(asn1_node_t **out) {
    if (!out) return ERROR_INVALID_ARGS;

    // Check if is already allocated
    if (*out) return ERROR_DATA_ALREADY_ALLOC;

    *out = calloc(1, sizeof(asn1_node_t));
    if (!*out) return ERROR_ALLOCATION;

    return PARSER_OK;
}

/**************************************************/
//                Stack Utils
/**************************************************/







#include "asn1_new_parser.h"

#include <string.h>

asn1_parser_error_t ctx_buffer_new(uint8_t *data, size_t dim, ctx_buffer_t *out) {
    if (!out) return -1;
    if (!data) return -1;

    out->dim = dim;
    out->data = data;

    return PARSER_OK;
}


uint8_t ctx_buffer_is_safe_offset(ctx_buffer_t buffer, size_t offset) {
    return offset < buffer.dim;
}

uint8_t ctx_buffer_is_safe_len(ctx_buffer_t buffer, size_t offset, size_t len) {
    return ctx_buffer_is_safe_offset(buffer, offset)
            && buffer.dim - offset >= len;
}

asn1_parser_error_t ctx_buffer_read(ctx_buffer_t buffer, size_t start_offset, size_t bytes_to_read, uint8_t **out) {
    // Check for read safety
    if (!out) return -1;
    
    if (!buffer.data) return -1;

    if (!ctx_buffer_is_safe_len(buffer, start_offset, bytes_to_read)) 
        return -1;

    *out = calloc(bytes_to_read, sizeof(uint8_t));
    if (!*out) return -1;

    memcpy(*out, buffer.data, bytes_to_read);

    return PARSER_OK;
}


asn1_parser_error_t tlv_extract_len(ctx_buffer_t buffer, size_t offset, uint8_t *num_bytes, uint64_t *len) {
    if (!num_bytes || !len) return -1;

    if (!buffer.data) return -1;

    // Safe read the len byte
    uint8_t l_byte;
    if (!ctx_buffer_is_safe_len(buffer, offset, sizeof(l_byte))) return -1;
    l_byte = buffer.data[offset];

    // Check the Len form
    uint8_t form = (l_byte & 0x80);

    // Long-form
    if (form != 0) {
        *num_bytes = (l_byte & 0x7F);

        if (*num_bytes > PARSER_MAX_NUM_BYTES_FOR_LEN) return -1;

        // Read the effective len
        offset++;
        if (!ctx_buffer_is_safe_len(buffer, offset, *num_bytes)) return -1;
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

    return PARSER_OK;
}


asn1_parser_error_t tlv_read_from_buffer(ctx_buffer_t buffer, size_t start_offset, tlv_t *tlv_out) {

}




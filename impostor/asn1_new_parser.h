#ifndef ASN1_PARSER_H
#define ASN1_PERSER_H

#include <stdint.h>
#include <stdlib.h>

/**************************************************/
//                ASN1 Tree Structs
/**************************************************/

typedef uint8_t asn1_tag_t;

typedef struct ctx_buffer_t {
    uint8_t *data;
    size_t dim;
    size_t offset;
} ctx_buffer_t;

// Zero-copy
typedef struct tlv_t {
    size_t offset_start;
    asn1_tag_t tag;              // Tag ASN1
    size_t tag_value_len;        // Length of Value
    size_t tag_value_len_bytes;  // Num Bytes of Length of Value
    size_t offset_data;          // Offset of the ctx_buffer
} tlv_t;

typedef struct asn1_node_t {
    asn1_tag_t tag;

    // Content if no constructed tag
    size_t data_dim;
    uint8_t *data;

    // Childs 
    size_t dim;
    size_t size;
    struct asn1_node_t **child_nodes;
} asn1_node_t;

typedef asn1_node_t * asn1_tree_t;

/**************************************************/
//                Stack Structs
/**************************************************/

typedef struct parser_entry_stack_t {
    asn1_node_t *node;

    // Stack context
    tlv_t tlv;
    size_t ret_len;

} parser_entry_stack_t;

typedef struct parser_stack_t {
    size_t dim;
    size_t size;
    parser_entry_stack_t **stack_entries;
} parser_stack_t;


#endif // ASN1_PERSER_H
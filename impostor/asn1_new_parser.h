/* asn1_parser -- An implementation of an ASN.1 DER parser.
 *
 * Luca Vinci <luca9vinci at gmail dot com>
 *
 * Parser developed with the goal of writing an SMB1 server
 * for intercepting NTLM hashes.
 *
 * The parser is minimal and builds a tree representing the
 * ASN.1 structure, with raw data that requires decoding.
 * 
 * ====================
 * ASN1 TAG Structure
 * ====================
 * 
 * A tag consists of two parts: the class and the number.
 * 
 *       7 6  5  4 3 2 1 0
 * TAG: |x|x||x||x|x|x|x|x|
 *      ^---^^-^^---------^
 *        |   |   |     
 *      Class | Number
 *           P/C
 * 
 * Class:
 *  - 00 -> Universal
 *  - 01 -> Application
 *  - 10 -> Context-specif
 *  - 11 -> Private
 * 
 * P/C:
 *  - 0 -> Primitive
 *  - 1 -> Constructed
 * 
 * ====================  
 * TLV Structure
 * ====================
 * 
 * The transfer syntax used by distinct encoding rules always follows
 * a Tag-Length-Value format, commonly referred to as a TLV triplet.
 * 
 * +-------------------------------+
 * |   |   +---------------------+ |
 * |   |   |   |   +-----------+ | |
 * | T | L | T | L | T | L | V | | |
 * |   |   |   |   +-----------+ | |  
 * |   |   +---------------------+ |
 * +-------------------------------+
 * 
 * 
 * The Length field in a TLV triplet specifies the number of bytes encoded
 * in the Value field. The Value field contains the actual data transmitted
 * between computers. 
 * 
 * - If the Value field contains fewer than 128 bytes, the Length field
 *   uses a single byte. Bit 7 of the Length byte is 0, and the remaining
 *   bits indicate the number of bytes in the Value field.
 * 
 * - If the Value field contains 128 bytes or more, bit 7 of the Length
 *   byte is set to 1, and the remaining bits specify the number of
 *   bytes used to encode the length itself.
 * 
 * Examples are illustrated below:
 * 
 * |0|0|1|1|0|1|0|0||x|x|x|x|x|x|x|x|x|x|x|x|x|x|...
 *  ^ ^-----------^  ^--------------------------^ 
 *  |  Length = 52           Value -> 52 Bytes
 *  |    
 * Bit representation for 0 <= Length <= 127 bytes
 * 
 * |1|0|0|0|0|0|1|0||0|0|0|1|0|0|1|1|0|1|0|0|0|1|1|0||x|x|x|x|x|x|x|x|...
 *  ^ ^-----------^  ^-----------------------------^  ^---------------^
 *  | Num of length bytes = 2       2 Bytes -> 4934       Value -> 4934 Bytes										
 *  |    
 * Bit representation for 128 <= Length <= 2^126 bytes
 *     
 */

#ifndef ASN1_PARSER_H
#define ASN1_PERSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>

/**************************************************/
//                Errors
/**************************************************/

#define PARSER_OK 0x00000000

#define ERROR_INVALID_ARGS 0x80000001
#define ERROR_UNSAFE_LEN 0x80000002
#define ERROR_ALLOCATION 0x80000003
#define ERROR_INVALID_BUFFER_DATA 0x80000004
#define ERROR_PARSER_MAX_NUM_BYTES_FOR_LEN 0x80000005
#define ERROR_UNSAFE_BUFFER_OFFSET 0x80000006
#define ERROR_REALLOC 0x80000007
#define ERROR_DATA_ALREADY_ALLOC 0x80000008
#define ERROR_NOTHING_TO_REALLOC 0x80000009

#define ERROR_INVALID_TREE 0x8000000a
#define ERROR_STACK_ALREADY_ALLOC 0x8000000b
#define ERROR_STACK_ENTRY_ALREADY_ALLOC 0x8000000c
#define ERROR_INVALID_STACK 0x8000000d

#define ERROR_MAX_NESTING_REACHED 0x8000000e
#define ERROR_POP_FROM_EMPTY_STACK 0x8000000f

#define ERROR_NODE_ALREADY_ALLOC 0x80000010
#define ERROR_TRY_ALLOC_PRIM_NODE 0x80000020
#define ERROR_INVALID_BUFFER 0x80000030

#define ERROR_OVERFLOW 0x80000040



typedef int32_t asn1_parser_error_t;

/**************************************************/
//                Constants
/**************************************************/

#define PARSER_MAX_NUM_BYTES_FOR_LEN 8  // 8 bytes


/**************************************************/
//                ASN1 Tree Structs
/**************************************************/

#define IS_CONSTRUCTED_ASN1_TAG(tag) ((tag & 0x20) != 0)

typedef uint8_t asn1_tag_t;

typedef struct ctx_buffer_t {
    size_t dim;
    uint8_t *data;
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


/**************************************************/
//                Parser Utils
/**************************************************/

/**
 * Returns a new ctx_buffer
 */
asn1_parser_error_t ctx_buffer_new(uint8_t *data, size_t dim, ctx_buffer_t *out);

/**
 * Function for safe read. It checks offsetand len safety.
 */
uint8_t ctx_buffer_is_safe_offset(ctx_buffer_t buffer, size_t offset);
uint8_t ctx_buffer_is_safe_len(ctx_buffer_t buffer, size_t offset, size_t len);

/**
 * Reads bytes_to_read from buffer and returns in out
 */
asn1_parser_error_t ctx_buffer_read(ctx_buffer_t buffer, size_t start_offset, size_t bytes_to_read, uint8_t **out);

/**
 * From a buffer retrieve a TLV
 */
asn1_parser_error_t tlv_read_from_buffer(ctx_buffer_t buffer, size_t start_offset, tlv_t *tlv_out);

/**
 * Extract len from a bytes. Checks for short-form or long-form.
 * Returns num_bytes that encode len and the effective len.
 */
asn1_parser_error_t tlv_extract_len(ctx_buffer_t buffer, size_t offset, size_t *num_bytes, uint64_t *len);

/**
 * Returns in out a pointer to a new asn1 node
 */
asn1_parser_error_t asn1_node_new(asn1_node_t **out, asn1_tag_t tag);

asn1_parser_error_t asn1_tree_free(asn1_node_t **tree);


/**************************************************/
//                Stack Utils
/**************************************************/

/**
 * Create new stack , new stack entry and function for check emptiness
 */
asn1_parser_error_t parser_stack_new(parser_stack_t **out);
asn1_parser_error_t parser_entry_stack_new(asn1_node_t *node, tlv_t tlv, parser_entry_stack_t **out);
asn1_parser_error_t parser_stack_empty(parser_stack_t *stack, uint8_t *out);

/**
 * Free functions for stack entry and for stack
 */
void parser_stack_free_entry(parser_entry_stack_t **entry);
void parser_stack_free(parser_stack_t **stack);

/**
 * Utilities for stack
 */
asn1_parser_error_t parser_stack_push(parser_stack_t *stack, parser_entry_stack_t *entry);
asn1_parser_error_t parser_stack_pop(parser_stack_t *stack);
asn1_parser_error_t parser_stack_top(parser_stack_t *stack, parser_entry_stack_t **out);


/**************************************************/
//                Main Parser
/**************************************************/

typedef void (*asn1_logger_t)(size_t ident, const char *format, va_list args);

asn1_parser_error_t parse(uint8_t *buffer, size_t len, asn1_node_t **out);


#endif // ASN1_PERSER_H
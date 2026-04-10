#ifndef ASN1_PARSER_H
#define ASN1_PARSER_H

#include <stdint.h>
#include <stdlib.h>

/**************************************************/
//                    ERRORS
/*************************************************/

#define PARSER_OK                                       0x00000000

#define PARSER_ERROR_LEN_LEN_BYTES_TOO_BIG              0x80000001
#define PARSER_ERROR_LEN_LEN_OVERFLOW                   0x80000002

#define PARSER_ERROR_INVALID_BUFFER                     0x80000003

#define PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT              0x80000004
#define PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY               0x80000005
#define PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY_VALUE         0x80000006

#define PARSER_ERROR_INVALID_BLOB                       0x80000007

#define PARSER_ERROR_ASN1_ENTRY_VALUE_LEN_TOO_BIG       0x80000008

#define PARSER_ERROR_FREE_ASN1_OBJ_ALLOC                0x80000009
#define PARSER_ERROR_FREE_ASN1_OBJ_REALLOC              0x8000000a

#define PARSER_ERROR_INVALID_ENTRY                      0x8000000b

#define PARSER_ERROR_APPEND_INVALID_OBJ                 0x8000000c
#define PARSER_ERROR_APPEND_REALLOC                     0x8000000d
#define PARSER_ERROR_APPEND_REALLOC_MAX_CHILD_REACHED   0x8000000e

#define PARSER_ERROR_STACK_INVALID_STACK                0x8000000f
#define PARSER_ERROR_STACK_MAX_DIM_EXCEEDED             0x80000010
#define PARSER_ERROR_STACK_LEN_DIM_EXCEEDED             0x80000011
#define PARSER_ERROR_STACK_REALLOC                      0x80000012
#define PARSER_ERROR_STACK_POP_FROM_EMPTY_STACK         0x80000013
#define PARSER_ERROR_STACK_TOP_FROM_EMPTY_STACK         0x80000014
#define PARSER_ERROR_STACK_ALLOCATION                   0x80000015
#define PARSER_ERROR_STACK_ENTRY_ALLOCATION             0x80000016
#define PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL            0x80000017
#define PARSER_ERROR_STACK_PUSH_ENTRY_IS_NULL           0x80000018

#define PARSER_ERROR_INVALID_TAG                        0x80000019

#define PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG              0x8000001a
#define PARSER_ERROR_MAX_ASN1_NUMERIC_SIZE              0x8000001b
#define PARSER_ERROR_MAX_ASN1_STRING_SIZE               0x8000001c
#define PARSER_ERROR_MAX_ASN1_OID_SIZE                  0x8000001d
#define PARSER_ERROR_MAX_ASN1_BOOLEAN_SIZE              0x8000001e          
#define PARSER_ERROR_MAX_ASN1_NULL_SIZE                 0x8000001f
#define PARSER_ERROR_MAX_ASN1_EOC_SIZE                  0x80000020
#define PARSER_ERROR_MAX_ASN1_ENUMERATED_SIZE           0x80000021
#define PARSER_ERROR_MAX_ASN1_GENERALIZED_TIME_SIZE     0x80000022
#define PARSER_ERROR_MAX_ASN1_UTC_TIME_SIZE             0x80000023
#define PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE     0x80000024

#define PARSER_ERROR_INVALID_TYPE_INFO_ENTRY            0x80000025

#define PARSER_ERROR_MAX_ASN1_NESTING_DEPTH             0x80000026

#define PARSER_ERROR_INVALID_ARG                        0x80000027

typedef int32_t asn1_parser_error;

/**************************************************/
//                    TYPES
/*************************************************/
// ASN.1 Types and respective Tags

#define ASN1_TYPE_EOC                       0x00
#define ASN1_TYPE_BOOLEAN                   0x01
#define ASN1_TYPE_INTEGER                   0x02
#define ASN1_TYPE_BIT_STRING                0x03
#define ASN1_TYPE_OCTET_STRING              0x04
#define ASN1_TYPE_NULL                      0x05
#define ASN1_TYPE_OBJECT_ID                 0x06

// Strings Types
#define ASN1_TYPE_OBJECT_DESCRIPTOR         0x07
#define ASN1_TYPE_REAL                      0x09
#define ASN1_TYPE_RELATIVE_OID              0x0d
#define ASN1_TYPE_UTC_TIME                  0x17
#define ASN1_TYPE_GENERALIZED_TIME          0x18
#define ASN1_TYPE_ENUMERATED                0x0a

#define ASN1_TYPE_UTF8_STRING               0x0c
#define ASN1_TYPE_UTF8_NUMERIC_STRING       0x12
#define ASN1_TYPE_PRINTABLE_STRING          0x13
#define ASN1_TYPE_T61_STRING                0x14
#define ASN1_TYPE_VIDEOTEX_STRING           0x15
#define ASN1_TYPE_IA5_STRING                0x16
#define ASN1_TYPE_GRAPHIC_STRING            0x19
#define ASN1_TYPE_VISIBLE_STRING            0x1a
#define ASN1_TYPE_GENERAL_STRING            0x1b
#define ASN1_TYPE_UNIVERSAL_STRING          0x1c
#define ASN1_TYPE_UNICODE_STRING            0x1e
#define ASN1_TYPE_CHARACTER_STRING          0x3d

// Construct Types
#define ASN1_TYPE_SEQUENCE                  0x30
#define ASN1_TYPE_SET                       0x31
#define ASN1_TYPE_EXTERNAL                  0x28
#define ASN1_TYPE_EMBEDDED_PDV              0x2b

// GSSAPI Tag
#define ASN1_TYPE_GSSAPI                    0x60

//Tags NegotiationToken
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT       0xa0
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP       0xa1

//Tags NegTokenInit
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTYPES          0xa0
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT_REQFLAGS           0xa1
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTOKEN          0xa2
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT_NEG_HINTS          0xa3
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHLISTMIC        0xa4

// Tags NegTokenResp
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP_NEGSTATE           0xa0
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP_SUPPORTEDMECH      0xa1
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP_RESPONSETOKEN      0xa2
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP_MECHLISTMIC        0xa3

typedef uint8_t asn1_type_t;

/**************************************************/
//                    Struct
/**************************************************/

/**
 * Structure for type handling. Includes the associated name, limit, node type
 * (root or leaf) useful for building the tree during parsing, and a possible
 * error in case the limit is exceeded.
 */
typedef struct types_info {
    asn1_type_t type;
    const char *name;
    size_t max_len;
    uint8_t flag;
    asn1_parser_error err;
} types_info;

/* 
 * Possible value of the ASN.1 node in the ASN.1 tree
 * resulting from the parsing.
 */
typedef struct asn1_entry {
    size_t len;
    uint8_t *value;
} asn1_entry;

/*
 * Node of the ASN.1 tree
 */
typedef struct asn1_obj {
    asn1_type_t type;
    struct asn1_entry *entry;
    size_t len;
    size_t dim;
    struct asn1_obj **list;
} asn1_obj;

/**************************************************/
//                PARSER UTILS
/**************************************************/

asn1_parser_error get_type_info_by_type(asn1_type_t type, const types_info **out);
asn1_parser_error is_root_node(asn1_type_t type, uint8_t *is_root);
uint8_t is_valid_type(asn1_type_t type);
uint8_t is_safe_asn1_length(size_t len, size_t offset, size_t max_len);
asn1_parser_error check_len_by_type(asn1_type_t type, size_t len);

/**************************************************/
//                 PARSER OBJECT 
/**************************************************/

asn1_entry * new_asn1_entry();
asn1_obj * new_asn1_obj(asn1_type_t type);
asn1_parser_error append_asn1_obj_list(asn1_obj **obj, asn1_obj *obj_to_append);
void free_asn1_entry(asn1_entry **entry);
asn1_parser_error free_asn1_obj(asn1_obj **obj);

/**************************************************/
//             PARSING FOR LENGHTS
/**************************************************/

uint8_t check_long_form(uint8_t b);
uint8_t extract_len_short_form(uint8_t b);
asn1_parser_error extract_len_long_form(uint8_t *buffer, uint8_t bytes, uint64_t *out_len);
asn1_parser_error parse_length(uint8_t *buffer, uint64_t *out_len, uint64_t *num_bytes_len);

/**************************************************/
//                PARSING TYPES
/**************************************************/

asn1_parser_error parse_blob(uint8_t type, const uint8_t *blob, size_t len, asn1_entry **entry);

/**************************************************/
//                STACK UTILS
/**************************************************/

/**
 * Structure describing an entry for the stack used
 * by the main parser.
 */
typedef struct parser_stack_entry {
    asn1_obj *obj;
    size_t ret_len;
    size_t effective_len;  
    size_t offset;  
    size_t num_bytes_len;
} parser_stack_entry;

/**
 * Structure for the stack used by the main parser
 */
typedef struct parser_stack {
    size_t dim;
    size_t len;
    parser_stack_entry **stack;
} parser_stack;

parser_stack_entry * new_parser_stack_entry();
parser_stack * new_parser_stack();
uint8_t parser_stack_is_empty(parser_stack *stack);
void free_parser_stack_entry(parser_stack_entry **entry);
asn1_parser_error free_parser_stack(parser_stack **stack);
asn1_parser_error parser_stack_realloc(parser_stack *stack);
asn1_parser_error parser_stack_push(parser_stack *stack, parser_stack_entry *entry);
asn1_parser_error parser_stack_pop(parser_stack *stack, parser_stack_entry **out);
asn1_parser_error parser_stack_top(parser_stack *stack, parser_stack_entry **out);

/**************************************************/
//                MAIN PARSER
/**************************************************/

asn1_parser_error parse(uint8_t *buffer, size_t len, asn1_obj **obj_out);

 


#endif // ASN1_PARSER_H
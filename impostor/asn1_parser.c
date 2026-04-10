/* asn1_parser -- An implementation of an ASN.1 DER parser.
 *
 * Luca Vinci <luca9vinci at gmail dot com>
 *
 * Parser developed with the goal of writing an SMB1 server
 * for intercepting NTLM hashes.
 *
 * The parser is minimal and builds a tree representing the
 * ASN.1 structure, with raw data that requires decoding.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "asn1_parser.h"

/**************************************************/
//                   CONSTANTS
/*************************************************/

/* Mask to determine from the most significant bit of the first byte whether the length is >= 128 */
#define PARSER_CHECK_LEN_BYTE_MASK              0x80         // 1000 0000
#define PARSER_EXTRACT_LEN_FROM_BYTES_MASK      0x7F         // 0111 1111

/* Size for TLV length */

#define PARSER_MAX_LEN_LEN_BYTES                8             // 8 bytes
#define PARSER_MAX_LEN_VALUE_BYTES              127           // 127 

/* Initialization sizes and maximum limits */
#define PARSER_INIT_DIM_LIST_ASN1_OBJ           10
#define PARSER_MAX_DIM_LIST_ASN1_OBJ            400
#define PARSER_MAX_ENTRY_VALUE_LEN              (4 * 1024)     // 4 KB

#define PARSER_INIT_DIM_STACK                   100
#define PARSER_MAX_DIM_STACK                    800

#define PARSER_MAX_ASN1_SIZE                    (64 * 1024)     // 64 KB
#define PARSER_MAX_ASN1_NUMERIC_SIZE            512             // 512 Bytes
#define PARSER_MAX_ASN1_STRING_SIZE             (4 * 1024)      // 4 KB
#define PARSER_MAX_ASN1_OID                     64              // 64 Bytes

#define PARSER_MAX_ASN1_BOOLEAN_SIZE            1               // 1 Byte
#define PARSER_MAX_ASN1_NULL_SIZE               0               // 0 Byte
#define PARSER_MAX_ASN1_EOC_SIZE                0               // 0 Byte
#define PARSER_MAX_ASN1_ENUMERATED_SIZE         1               // 1 Byte
#define PARSER_MAX_ASN1_GENERALIZED_TIME_SIZE   32              // 32 Bytes
#define PARSER_MAX_ASN1_UTC_TIME_SIZE           16              // 16 Bytes 
#define PARSER_MAX_ASN1_DEFAULT                 (64 * 1024)     // 64 KB 
#define PARSER_MAX_ASN1_NESTING_DEPTH           16 

#define LEAF_NODE 0x00
#define ROOT_NODE 0x01


/* "Table" of types. Array of types_info. */
const types_info tags[] = {
    // Base Types
    {ASN1_TYPE_EOC,                     "ASN1_TYPE_EOC",                   PARSER_MAX_ASN1_EOC_SIZE,                0, PARSER_ERROR_MAX_ASN1_EOC_SIZE},
    {ASN1_TYPE_BOOLEAN,                 "ASN1_TYPE_BOOLEAN",               PARSER_MAX_ASN1_BOOLEAN_SIZE,            0, PARSER_ERROR_MAX_ASN1_BOOLEAN_SIZE},
    {ASN1_TYPE_INTEGER,                 "ASN1_TYPE_INTEGER",               PARSER_MAX_ASN1_NUMERIC_SIZE,            0, PARSER_ERROR_MAX_ASN1_NUMERIC_SIZE},
    {ASN1_TYPE_BIT_STRING,              "ASN1_TYPE_BIT_STRING",            PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_OCTET_STRING,            "ASN1_TYPE_OCTET_STRING",          PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_NULL,                    "ASN1_TYPE_NULL",                  PARSER_MAX_ASN1_NULL_SIZE,               0, PARSER_ERROR_MAX_ASN1_NULL_SIZE},
    {ASN1_TYPE_OBJECT_ID,               "ASN1_TYPE_OBJECT_ID",             PARSER_MAX_ASN1_OID,                     0, PARSER_ERROR_MAX_ASN1_OID_SIZE},

    {ASN1_TYPE_OBJECT_DESCRIPTOR,       "ASN1_TYPE_OBJECT_DESCRIPTOR",     PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},  // Contains only readable ASCII characters.
    {ASN1_TYPE_REAL,                    "ASN1_TYPE_REAL",                  PARSER_MAX_ASN1_NUMERIC_SIZE,            0, PARSER_ERROR_MAX_ASN1_NUMERIC_SIZE},
    {ASN1_TYPE_RELATIVE_OID,            "ASN1_TYPE_RELATIVE_OID",          PARSER_MAX_ASN1_OID,                     0, PARSER_ERROR_MAX_ASN1_OID_SIZE},
    {ASN1_TYPE_UTC_TIME,                "ASN1_TYPE_UTC_TIME",              PARSER_MAX_ASN1_UTC_TIME_SIZE,           0, PARSER_ERROR_MAX_ASN1_UTC_TIME_SIZE},
    {ASN1_TYPE_GENERALIZED_TIME,        "ASN1_TYPE_GENERALIZED_TIME",      PARSER_MAX_ASN1_GENERALIZED_TIME_SIZE,   0, PARSER_ERROR_MAX_ASN1_UTC_TIME_SIZE},
    {ASN1_TYPE_ENUMERATED,              "ASN1_TYPE_ENUMERATED",            PARSER_MAX_ASN1_ENUMERATED_SIZE,         0, PARSER_ERROR_MAX_ASN1_ENUMERATED_SIZE},

    // Strings Types
    {ASN1_TYPE_UTF8_STRING,             "ASN1_TYPE_UTF8_STRING",           PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_UTF8_NUMERIC_STRING,     "ASN1_TYPE_UTF8_NUMERIC_STRING",   PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_PRINTABLE_STRING,        "ASN1_TYPE_PRINTABLE_STRING",      PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_T61_STRING,              "ASN1_TYPE_T61_STRING",            PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_VIDEOTEX_STRING,         "ASN1_TYPE_VIDEOTEX_STRING",       PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_IA5_STRING,              "ASN1_TYPE_IA5_STRING",            PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_GRAPHIC_STRING,          "ASN1_TYPE_GRAPHIC_STRING",        PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_VISIBLE_STRING,          "ASN1_TYPE_VISIBLE_STRING",        PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_GENERAL_STRING,          "ASN1_TYPE_GENERAL_STRING",        PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_UNIVERSAL_STRING,        "ASN1_TYPE_UNIVERSAL_STRING",      PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_UNICODE_STRING,          "ASN1_TYPE_UNICODE_STRING",        PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_CHARACTER_STRING,        "ASN1_TYPE_CHARACTER_STRING",      PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},

    // Construct Types
    {ASN1_TYPE_SEQUENCE,                "ASN1_TYPE_SEQUENCE",              PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SET,                     "ASN1_TYPE_SET",                   PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_EXTERNAL,                "ASN1_TYPE_EXTERNAL",              PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_EMBEDDED_PDV,            "ASN1_TYPE_EMBEDDED_PDV",          PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},

    // GSSAPI Tag
    {ASN1_TYPE_GSSAPI,                  "ASN1_TYPE_GSSAPI",                PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},

    //Tags NegotiationToken
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT,     "ASN1_TYPE_SPNEGO_NEGTOKENINIT",   PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENRESP,     "ASN1_TYPE_SPNEGO_NEGTOKENRESP",   PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},

    //Tags NegTokenInit
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTYPES,   "ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTYPES",   PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT_REQFLAGS,    "ASN1_TYPE_SPNEGO_NEGTOKENINIT_REQFLAGS",    PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTOKEN,   "ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHTOKEN",   PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT_NEG_HINTS,   "ASN1_TYPE_SPNEGO_NEGTOKENINIT_NEG_HINTS",   PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHLISTMIC, "ASN1_TYPE_SPNEGO_NEGTOKENINIT_MECHLISTMIC", PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    
    // Tags NegTokenResp
    {ASN1_TYPE_SPNEGO_NEGTOKENRESP_NEGSTATE,      "ASN1_TYPE_SPNEGO_NEGTOKENRESP_NEGSTATE",      PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENRESP_SUPPORTEDMECH, "ASN1_TYPE_SPNEGO_NEGTOKENRESP_SUPPORTEDMECH", PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENRESP_RESPONSETOKEN, "ASN1_TYPE_SPNEGO_NEGTOKENRESP_RESPONSETOKEN", PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_NEGTOKENRESP_MECHLISTMIC,   "ASN1_TYPE_SPNEGO_NEGTOKENRESP_MECHLISTMIC",   PARSER_MAX_ASN1_DEFAULT, 1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE}
};

#define TAGS_SIZE (sizeof(tags) / sizeof(tags[0]))


/**************************************************/
//                PARSER UTILS
/**************************************************/

/**
 * Utility function to get, given a type, its entry
 * in the tags table.
 */
asn1_parser_error get_type_info_by_type(asn1_type_t type, const types_info **out) {
    if (!out) return PARSER_ERROR_INVALID_ARG;
    for (size_t i = 0; i < TAGS_SIZE; i++) {
        if (tags[i].type == type) {
            *out = &tags[i];
            return PARSER_OK;
        }
    }
    return PARSER_ERROR_INVALID_TAG;
}

/**
 * Utility function to determine if a type is of "root" type
 * in the ASN.1 tree.
 */
asn1_parser_error is_root_node(asn1_type_t type, uint8_t *is_root) {
    if (!is_root) return PARSER_ERROR_INVALID_ARG;

    const types_info *t_i;
    asn1_parser_error res = get_type_info_by_type(type, &t_i);

    if (res < PARSER_OK) return res;

    *is_root = (t_i->flag & ROOT_NODE) ? 1 : 0;

    return PARSER_OK;
}

uint8_t is_valid_type(asn1_type_t type) {
    const types_info *t_i;
    return (get_type_info_by_type(type, &t_i) == PARSER_OK) ? 1 : 0;
}

/**
 * Function that checks if a length, given an offset and a maximum
 * length of the blob, is safe. It verifies that it does not exceed
 * the maximum length starting from the offset. It also checks that
 * the offset is not greater than max_len for a safer validation.
 */
uint8_t is_safe_asn1_length(size_t len, size_t offset, size_t max_len) {
    return offset <= max_len && len <= max_len - offset;
}

/**
 * Function that, given a type and a length, checks that the length
 * respects the limits for the respective type. Performs a lookup
 * in the "tags" table.
 */
asn1_parser_error check_len_by_type(asn1_type_t type, size_t len) {
    const types_info *t_i;
    asn1_parser_error res = get_type_info_by_type(type, &t_i);
    if (res < PARSER_OK) return res;
    if (len > t_i->max_len) return t_i->err;

    return PARSER_OK;
}

/**************************************************/
//                 PARSER OBJECT 
/**************************************************/

/**
 * Creates an entry. An entry is part of the asn1_obj structure,
 * which is a node of the ASN.1 tree. An asn1_obj node will have
 * an entry if it is a leaf-type node.
 */
asn1_entry * new_asn1_entry() {
    asn1_entry * entry = malloc(sizeof(struct asn1_entry));

    if (!entry) return NULL;

    entry->len = 0;
    entry->value = NULL;

    return entry;
}

/**
 * Creates an asn1_obj, which is a node of the ASN.1 tree.
 * Each "root"-type node will have a list of children.
 */
asn1_obj * new_asn1_obj(asn1_type_t type) {
    asn1_obj * obj = malloc(sizeof(struct asn1_obj));

    if (!obj) return NULL;

    obj->type = 0;
    obj->entry = NULL;
    obj->len = 0;
    obj->dim = 0;
    obj->list = NULL;

    // If the node is of root type, allocate a list
    uint8_t is_root;
    asn1_parser_error res = is_root_node(type, &is_root);
    if (res < PARSER_OK) {
        free(obj);
        return NULL;
    }

    if (is_root) {
        obj->dim = PARSER_INIT_DIM_LIST_ASN1_OBJ;
        obj->list = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_LIST_ASN1_OBJ);

        if (!obj->list) {
            free(obj);
            return NULL;
        }

        memset(obj->list, 0, sizeof(struct asn1_obj *) * PARSER_INIT_DIM_LIST_ASN1_OBJ);
    }

    return obj;
}

/**
 * Appends to the list of a "root"-type node.
 */
asn1_parser_error append_asn1_obj_list(asn1_obj **obj, asn1_obj *obj_to_append) {
    if (!obj || !*obj || !obj_to_append) return PARSER_ERROR_APPEND_INVALID_OBJ;

    if ((*obj)->dim >= PARSER_MAX_DIM_LIST_ASN1_OBJ) return PARSER_ERROR_APPEND_REALLOC_MAX_CHILD_REACHED; 

    if ((*obj)->len >= (*obj)->dim) {

        asn1_obj **tmp = realloc((*obj)->list, sizeof(struct asn1_obj *) * ((*obj)->dim * 2));
        if(!tmp) return PARSER_ERROR_APPEND_REALLOC;

        (*obj)->list = tmp;
        (*obj)->dim *= 2;
    }

    (*obj)->list[(*obj)->len++] = obj_to_append;

    return PARSER_OK;
}

/**
 * Frees an asn1_entry.
 */
void free_asn1_entry(asn1_entry **entry) {
    if (!entry || !*entry) return;
    
    if ((*entry)->value) {
        free((*entry)->value);
        (*entry)->value = NULL;
    }

    free(*entry);
    *entry = NULL;
}

/**
 * Frees an entire ASN.1 tree including the entries of root nodes.
 * Uses a stack to store each node and free it.
 */
asn1_parser_error free_asn1_obj(asn1_obj **obj) {
    if (!obj || !*obj) return PARSER_OK;

    // Points to the top of the stack
    size_t stack_top = 0;

    // Initial capacity of the stack
    size_t stack_cap = PARSER_INIT_DIM_STACK;
    asn1_obj **stack = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_STACK);

    if (!stack) return PARSER_ERROR_FREE_ASN1_OBJ_ALLOC;

    // Push the root node of the tree onto the stack
    stack[stack_top++] = *obj;

    while (stack_top > 0) {
        // Perform a top operation on the stack to get the first element
        asn1_obj *act_obj = stack[stack_top - 1];

        // If it has a non-empty list, proceed to free the children
        if (act_obj->list) {
            for (size_t i = 0; i < act_obj->len; i++) {
                // For each child, push it onto the stack
                // If necessary, the stack is reallocated to expand its memory
                if (stack_top == stack_cap) {
                    asn1_obj **tmp = realloc(stack, sizeof(struct asn1_obj *) * (stack_cap * 2));

                    // If the reallocation fails, we must proceed to free the entire stack
                    if (!tmp) {
                        while (stack_top > 0) {
                            asn1_obj *o = stack[--stack_top];
                            free_asn1_entry(&o->entry);
                            free(o);
                        }
                        free(stack);
                        return PARSER_ERROR_FREE_ASN1_OBJ_REALLOC;
                    }
                    stack = tmp;
                    stack_cap *= 2;
                }
                // Push the child onto the stack
                stack[stack_top++] = act_obj->list[i];
            }

            // Once all children have been pushed, free the list and
            // start over from the beginning
            free(act_obj->list);
            act_obj->list = NULL;
            act_obj->len = 0;
            continue;
        }

        // If it has no list, it means it is a leaf or a node previously
        // freed from the list.
        // So proceed to free the entry if it has one, pop it from the stack, and free the node.
        free_asn1_entry(&act_obj->entry);
        free(act_obj);

        stack_top--;
    }
    
    // The stack is empty, so everything has been freed
    // or there was nothing to free.
    // Free the stack pointer.
    free(stack);
    *obj = NULL;
    return PARSER_OK;
}

/**************************************************/
//             PARSING FOR LENGHTS
/**************************************************/

/**
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
 */

/**
 * Function that, given a length byte, returns:
 *  0 : if the first bit is zero (length <= 127)
 *  1 : if the first bit is one  (length >= 128)
 */
uint8_t check_long_form(uint8_t b) {
    return b & PARSER_CHECK_LEN_BYTE_MASK;
}

/**
 * Function that, given a byte, extracts the value using a bitmask.
 * Used to extract the length value in short-form or the number of bytes
 * for long-form length encoding.
 */
uint8_t extract_len_short_form(uint8_t b) {
    return b & PARSER_EXTRACT_LEN_FROM_BYTES_MASK;
}

/**
 * Extracts the length of V in a TLV. Checks that the number of bytes
 * does not exceed 8. 
 * Exceeding 8 bytes would indicate a length larger than a 64-bit unsigned
 * integer, which cannot be stored. Using 64 bits is a reasonable choice,
 * as V could potentially have up to 2^64-1 bytes, which is practical
 * even for non-standard cryptographic data blobs (e.g., RSA, etc.).
 */
asn1_parser_error extract_len_long_form(uint8_t *buffer, uint8_t bytes, uint64_t *out_len) {
    if (!buffer || !out_len) return PARSER_ERROR_INVALID_BUFFER;

    if (bytes > PARSER_MAX_LEN_LEN_BYTES) return PARSER_ERROR_LEN_LEN_BYTES_TOO_BIG;

    uint64_t len = 0;
    while (bytes > 0) {
        uint64_t b = *buffer++;
        len = (len << 8) | b;
        bytes--;
    }

    *out_len = len;
    return PARSER_OK;
}

/**
 * Function that, given a pointer to the buffer at the position
 * for extracting the length, retrieves the length of the Value in bytes,
 * as well as the number of bytes used to encode the length.
 */
asn1_parser_error parse_length(uint8_t *buffer, uint64_t *out_len, uint64_t *num_bytes_len) {
    if (!buffer || !out_len || !num_bytes_len) return PARSER_ERROR_INVALID_BUFFER;

    uint8_t is_long_form = check_long_form(*(buffer));
    uint64_t b = extract_len_short_form(*(buffer)); // Get the length
    *num_bytes_len = 1;
    if (is_long_form) {
        uint64_t b_aux;
        *num_bytes_len += b;
        int32_t res = extract_len_long_form(buffer + 1, b, &b_aux);
        
        if (res < PARSER_OK) return res;
        b = b_aux;
    }
    
    *out_len = b;
    return PARSER_OK;
}

/**************************************************/
//                PARSING TYPES
/**************************************************/

/**
 * Function that, given a type, a blob (pointer to the buffer at the relevant position),
 * and a length, returns an asn1_entry containing the "raw" content from the buffer.
 * The entry will include the length in bytes of the raw content and a buffer
 * holding the raw data. 
 * This is useful for interpreting the values later with specific functions,
 * e.g., evaluating Integer, STRING, etc.
 */
asn1_parser_error parse_blob(uint8_t type, const uint8_t *blob, size_t len, asn1_entry **entry) {
    if (!entry) return PARSER_ERROR_INVALID_ENTRY;

    if (!blob) {
        *entry = NULL;
        return PARSER_ERROR_INVALID_BLOB;
    }

    asn1_parser_error res;
    if ((res = check_len_by_type(type, len)) < PARSER_OK) {
        *entry = NULL;
        return res;
    }

    *entry = new_asn1_entry();

    if (!*entry) {
        *entry = NULL;
        return PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY;
    }

    if (len == 0) {
        (*entry)->len = 0;
        (*entry)->value = NULL;
        return PARSER_OK;
    }

    (*entry)->len = len;
    (*entry)->value = malloc(sizeof(uint8_t) * len);

    if (!(*entry)->value) {
        free_asn1_entry(entry);
        *entry = NULL;
        return PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY_VALUE;
    }

    memcpy((*entry)->value, blob, len);

    return PARSER_OK;
}

/**************************************************/
//                STACK UTILS
/**************************************************/

parser_stack_entry * new_parser_stack_entry() {
    parser_stack_entry * entry = malloc(sizeof(struct parser_stack_entry));

    if (!entry) return NULL;

    entry->obj = NULL;
    entry->ret_len = 0;
    entry->offset = 0;
    entry->effective_len = 0;
    entry->num_bytes_len = 0;

    return entry;
}

parser_stack * new_parser_stack() {
    parser_stack * stack = malloc(sizeof(struct parser_stack));

    if(!stack) return NULL;

    stack->dim = PARSER_INIT_DIM_STACK;
    stack->len = 0;
    stack->stack = malloc(sizeof(parser_stack_entry *) * PARSER_INIT_DIM_STACK);

    if (!stack->stack) {
        free(stack);
        return NULL;
    }

    memset(stack->stack, 0, sizeof(parser_stack_entry *) * PARSER_INIT_DIM_STACK);

    return stack;
}

uint8_t parser_stack_is_empty(parser_stack *stack) {
    if (!stack) return 1;
    return stack->len > 0 ? 0 : 1;
}

/**
 * Does not free obj or parent, but clears the pointers.
 * The actual objects belong to asn1_obj, which is the
 * parsed structure. 
 * Freeing asn1_obj will release them.
 */
void free_parser_stack_entry(parser_stack_entry **entry) {
    if (!entry || !*entry) return;

    (*entry)->obj = NULL;

    free(*entry);
    *entry = NULL;
}

/**
 * Frees the stack used for parsing.
 * Does not free the asn1_obj objects.
 */
asn1_parser_error free_parser_stack(parser_stack **stack) {
    if (!stack || !*stack) return PARSER_ERROR_STACK_INVALID_STACK;

    if (!(*stack)->stack) {
        free(*stack);
        *stack = NULL;
        return PARSER_OK;
    }

    if ((*stack)->dim > PARSER_MAX_DIM_STACK) return PARSER_ERROR_STACK_MAX_DIM_EXCEEDED;
    if ((*stack)->len > PARSER_MAX_DIM_STACK ||
        (*stack)->len > (*stack)->dim) return PARSER_ERROR_STACK_LEN_DIM_EXCEEDED;

    for (size_t i = 0; i < (*stack)->len; i++) {
        free_parser_stack_entry(&((*stack)->stack[i]));
    }

    free((*stack)->stack);
    (*stack)->stack = NULL;

    free(*stack);
    *stack = NULL;

    return PARSER_OK;
}

/**
 * Reallocates the stack. If it fails, the state remains unchanged and an error is returned.
 * Freeing the memory is the caller's responsibility.
 */
asn1_parser_error parser_stack_realloc(parser_stack *stack) {
    if (!stack || !stack->stack) return PARSER_ERROR_STACK_INVALID_STACK;

    if ((stack->dim * 2) > PARSER_MAX_DIM_STACK) return PARSER_ERROR_STACK_MAX_DIM_EXCEEDED;

    parser_stack_entry ** tmp = realloc(stack->stack, sizeof(parser_stack_entry *) * (stack->dim) * 2);

    if (!tmp) return PARSER_ERROR_STACK_REALLOC;

    stack->stack = tmp;
    stack->dim *= 2;

    return PARSER_OK;
}

/**
 * Pushes onto the stack. Automatically reallocates if needed.
 * Returns an error if the push fails.
 * Freeing the memory is the caller's responsibility.
 */
asn1_parser_error parser_stack_push(parser_stack *stack, parser_stack_entry *entry) {
    if (!stack || !entry || !stack->stack) return PARSER_ERROR_STACK_INVALID_STACK;

    if (stack->len >= PARSER_MAX_ASN1_NESTING_DEPTH) return PARSER_ERROR_MAX_ASN1_NESTING_DEPTH;

    if (!entry) return PARSER_ERROR_STACK_PUSH_ENTRY_IS_NULL;
    if (!entry->obj) return PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL;

    asn1_parser_error res;
    if (stack->len >= stack->dim) {
        if ((res = parser_stack_realloc(stack)) < PARSER_OK) return res;
    }

    stack->stack[stack->len++] = entry;
    return PARSER_OK;
}

/**
 * Pops from the stack. Does not free the stack entry and returns it.
 * If NULL, performs a pop only.
 */
asn1_parser_error parser_stack_pop(parser_stack *stack, parser_stack_entry **out) {
    if (!stack || !stack->stack) return PARSER_ERROR_STACK_INVALID_STACK;
    if (stack->len <= 0) return PARSER_ERROR_STACK_POP_FROM_EMPTY_STACK;

    stack->len--;
    if (out) *out = stack->stack[stack->len]; 
    
    stack->stack[stack->len] = NULL;

    return PARSER_OK;
}

asn1_parser_error parser_stack_top(parser_stack *stack, parser_stack_entry **out) {
    if (!stack || !stack->stack || !out) return PARSER_ERROR_STACK_INVALID_STACK;

    if (stack->len <= 0) return PARSER_ERROR_STACK_TOP_FROM_EMPTY_STACK;

    *out = stack->stack[stack->len - 1];
    return PARSER_OK;
}

/**************************************************/
//                MAIN PARSER
/**************************************************/

asn1_parser_error parse(uint8_t *buffer, size_t len, asn1_obj **obj_out) {
    if (len > PARSER_MAX_ASN1_SIZE) return PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG;

    asn1_parser_error res;

    if (!buffer || !obj_out) return PARSER_ERROR_INVALID_BUFFER;

    // Create "root" object
    asn1_type_t type = *buffer;

    if (!is_valid_type(type)) {
        
        return PARSER_ERROR_INVALID_TAG;
    }

    asn1_obj *obj = new_asn1_obj(type);
    if (!obj) return PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT;

    uint64_t act_len, num_bytes;
    res = parse_length(buffer + 1, &act_len, &num_bytes);
    if (res < PARSER_OK) {
        free_asn1_obj(&obj);
        return res;
    }

    if (!is_safe_asn1_length(act_len, 0, len)) {
        free_asn1_obj(&obj);
        return PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG;
    }

    obj->type = type;
    obj->entry = NULL;

    // Check if obj is a leaf
    uint8_t is_root;
    res = is_root_node(type, &is_root);
    if (res < PARSER_OK) {
        free_asn1_obj(&obj);
        return res;
    }
    
    if (!is_root) {
        // Create object entry. Extract the blob and create an entry to place in obj
        asn1_entry *entry;
        res = parse_blob(type, buffer + 1 + num_bytes, act_len, &entry);
        if (res < PARSER_OK) {
            free_asn1_obj(&obj);
            return res;
        }
        obj->entry = entry;
        *obj_out = obj;
        return PARSER_OK;
    }

    // Not a leaf. Create a stack and push the entry onto it.
    parser_stack *stack = new_parser_stack();
    if (!stack) {
        free_asn1_obj(&obj);
        return PARSER_ERROR_STACK_ALLOCATION;
    }

    parser_stack_entry *stack_entry = new_parser_stack_entry();
    if (!stack_entry) {
        free_parser_stack(&stack);
        free_asn1_obj(&obj);
        return PARSER_ERROR_STACK_ENTRY_ALLOCATION;
    }

    stack_entry->obj = obj;
    stack_entry->effective_len = 1 + num_bytes + act_len;
    stack_entry->num_bytes_len = num_bytes;
    stack_entry->offset = 0;
    stack_entry->ret_len = 0;

    res = parser_stack_push(stack, stack_entry);
    if (res < PARSER_OK) {
        free_parser_stack(&stack);
        free_asn1_obj(&obj);
        return res;
    }

    while (!parser_stack_is_empty(stack)) {
        parser_stack_entry *tmp_stack_entry;
        res = parser_stack_top(stack, &tmp_stack_entry);
        if (res < PARSER_OK) {
            free_parser_stack(&stack);
            free_asn1_obj(&obj);
            return res;
        }

        // Check if the obj of the stack entry is NULL
        if (!tmp_stack_entry->obj) {
            free_parser_stack(&stack);
            free_asn1_obj(&obj);
            return PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL;
        }

#ifdef ASN1_PARSER_DEBUG
        printf("----------------------\n");
        printf("TOP from Stack:\n Tag: 0x%x\n", tmp_stack_entry->obj->type);
#endif

        // It is of "root" type
        res = is_root_node(tmp_stack_entry->obj->type, &is_root);
        if (res < PARSER_OK) {
            free_parser_stack(&stack);
            free_asn1_obj(&obj);
            return res;
        }
        if (is_root) {

#ifdef ASN1_PARSER_DEBUG
            printf("Type \"root\".\n");
            printf("effective_len: %d\n", tmp_stack_entry->effective_len);
            printf("num_bytes_len: %d\n", tmp_stack_entry->num_bytes_len);
            printf("offset: %d\n", tmp_stack_entry->offset);
            printf("ret_len: %d\n", tmp_stack_entry->ret_len);
#endif

            if (tmp_stack_entry->ret_len >= (tmp_stack_entry->effective_len - 1 - tmp_stack_entry->num_bytes_len)) {
                size_t temp_eff_len = tmp_stack_entry->effective_len;
                res = parser_stack_pop(stack, NULL);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return res;
                }
                
                // Modify the parent's ret_len
                if (!parser_stack_is_empty(stack)) {
                    parser_stack_entry *top_stack_entry;
                    res = parser_stack_top(stack, &top_stack_entry);
                    if (res < PARSER_OK) {
                        free_parser_stack(&stack);
                        free_asn1_obj(&obj);
                        return res;
                    }
                    top_stack_entry->ret_len += temp_eff_len;
                }

            }
            else {
                type = *(buffer + tmp_stack_entry->offset + 1 + tmp_stack_entry->num_bytes_len + tmp_stack_entry->ret_len);
                
                if (!is_valid_type(type)) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return PARSER_ERROR_INVALID_TAG;
                }

                asn1_obj * tmp_obj = new_asn1_obj(type);
                if (!tmp_obj) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT;
                }

                tmp_obj->type = type;
                tmp_obj->entry = NULL;

                parser_stack_entry *new_tmp_stack_entry = new_parser_stack_entry();
                if (!new_tmp_stack_entry) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_asn1_obj(&tmp_obj);
                    return PARSER_ERROR_STACK_ENTRY_ALLOCATION;
                }
                
                res = parse_length(
                        buffer + tmp_stack_entry->offset + 1 + tmp_stack_entry->num_bytes_len + 1 + tmp_stack_entry->ret_len,
                        &act_len, &num_bytes
                );

                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_asn1_obj(&tmp_obj);
                    free_parser_stack_entry(&new_tmp_stack_entry);
                    return res;
                }

                if (!is_safe_asn1_length(act_len, tmp_stack_entry->offset + 1 + tmp_stack_entry->num_bytes_len + 1 + tmp_stack_entry->ret_len, len)) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_asn1_obj(&tmp_obj);
                    return PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG;
                }

                new_tmp_stack_entry->obj = tmp_obj;
                new_tmp_stack_entry->offset = tmp_stack_entry->offset 
                                                + 1 + tmp_stack_entry->num_bytes_len 
                                                + tmp_stack_entry->ret_len;
                new_tmp_stack_entry->num_bytes_len = num_bytes;
                new_tmp_stack_entry->effective_len = 1 + num_bytes + act_len;
                new_tmp_stack_entry->ret_len = 0;

                // Append to the current node's list
                res = append_asn1_obj_list(&tmp_stack_entry->obj, tmp_obj);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_asn1_obj(&tmp_obj);
                    free_parser_stack_entry(&new_tmp_stack_entry);
                    return res;
                }
                
                // Push the entry onto the stack
                res = parser_stack_push(stack, new_tmp_stack_entry);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_parser_stack_entry(&new_tmp_stack_entry);
                    return res;
                }
            }
        }

        // It is of "leaf" type
        else {

#ifdef ASN1_PARSER_DEBUG
            printf("Type \"leaf\".\n");
            printf("effective_len: %d\n", tmp_stack_entry->effective_len);
            printf("num_bytes_len: %d\n", tmp_stack_entry->num_bytes_len);
            printf("offset: %d\n", tmp_stack_entry->offset);
            printf("ret_len: %d\n", tmp_stack_entry->ret_len);
#endif
            asn1_entry *obj_entry;
            res = parse_blob(tmp_stack_entry->obj->type, buffer + 
                                tmp_stack_entry->offset +
                                1 + tmp_stack_entry->num_bytes_len +
                                tmp_stack_entry->ret_len,
                            tmp_stack_entry->effective_len - 1 - tmp_stack_entry->num_bytes_len, 
                            &obj_entry);
            if (!obj_entry) {
                free_parser_stack(&stack);
                free_asn1_obj(&obj);
                return PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY;
            }

            tmp_stack_entry->obj->entry = obj_entry;
            
            size_t ret_len_aux = tmp_stack_entry->effective_len;

            // Pop leaf
            res = parser_stack_pop(stack, NULL);
            if (res < PARSER_OK) {
                free_parser_stack(&stack);
                free_asn1_obj(&obj);
                return res;
            }

            // Modify the parent's ret_len
            if (!parser_stack_is_empty(stack)) {
                parser_stack_entry *top_stack_entry;
                res = parser_stack_top(stack, &top_stack_entry);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return res;
                }

                // Modify the parent's ret_len
                top_stack_entry->ret_len += ret_len_aux;
            }
        }
    }

    *obj_out = obj;
    free_parser_stack(&stack);
    return PARSER_OK;
}

/************************************ */

static void print_indent(int indent) {
    for (int i = 0; i < indent; i++) {
        printf("|  "); // 2 spazi per livello
    }
}


void asn1_print(const asn1_obj *obj, int indent) {
    if (!obj) return;

    print_indent(indent);
    printf("\n");

    print_indent(indent);
    printf("ASN.1 Object\n");

    print_indent(indent);
    printf("Type: 0x%02x\n", obj->type);
    

    // Nodo foglia
    if (obj->entry && obj->entry->value) {
        print_indent(indent);
        printf("Value (len=%zu): ", obj->entry->len);

        for (size_t i = 0; i < obj->entry->len; i++) {
            printf("%02X ", obj->entry->value[i]);
        }
        printf("\n");
    }

    // Nodo composto: ha figli
    if (obj->list && obj->len > 0) {
        print_indent(indent);
        printf("Children (%zu):\n", obj->len);

        for (size_t i = 0; i < obj->len; i++) {
            asn1_print(obj->list[i], indent + 1);
        }
    }
}

#if 0

int main() {

    // Test buffer

    // Classic ASN.1 DER 
    unsigned char buffer[] = {0x30, 0x23, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03,
                              0x13, 0x06, 0x54, 0x65, 0x73, 0x74, 0x43, 0x4e, 0x31, 0x10, 0x30,
                              0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07, 0x54, 0x65, 0x73,
                              0x74, 0x4f, 0x72, 0x67};

    // ASN.1 DER - SPNEGO
    unsigned char buffer2[] = {0xa1,0x81,0xf6,0x30,0x81,0xf3,0xa0,0x03,0x0a,0x01,0x01,0xa1,0x0c,0x06,0x0a,0x2b,
                               0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a,0xa2,0x81,0xdd,0x04,0x81,0xda,0x4e,
                               0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00,0x08,0x00,0x08,0x00,0x38,
                               0x00,0x00,0x00,0x15,0x82,0x89,0xe2,0xc4,0xba,0x87,0xa2,0x65,0xde,0x9e,0x09,0x00,
                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x9a,0x00,0x9a,0x00,0x40,0x00,0x00,0x00,0x05,
                               0x02,0xce,0x0e,0x00,0x00,0x00,0x0f,0x38,0x00,0x4e,0x00,0x49,0x00,0x49,0x00,0x02,
                               0x00,0x08,0x00,0x38,0x00,0x4e,0x00,0x49,0x00,0x49,0x00,0x01,0x00,0x1e,0x00,0x57,
                               0x00,0x49,0x00,0x4e,0x00,0x2d,0x00,0x31,0x00,0x46,0x00,0x58,0x00,0x34,0x00,0x55,
                               0x00,0x4d,0x00,0x50,0x00,0x53,0x00,0x34,0x00,0x54,0x00,0x42,0x00,0x04,0x00,0x34,
                               0x00,0x57,0x00,0x49,0x00,0x4e,0x00,0x2d,0x00,0x31,0x00,0x46,0x00,0x58,0x00,0x34,
                               0x00,0x55,0x00,0x4d,0x00,0x50,0x00,0x53,0x00,0x34,0x00,0x54,0x00,0x42,0x00,0x2e,
                               0x00,0x38,0x00,0x4e,0x00,0x49,0x00,0x49,0x00,0x2e,0x00,0x4c,0x00,0x4f,0x00,0x43,
                               0x00,0x41,0x00,0x4c,0x00,0x03,0x00,0x14,0x00,0x38,0x00,0x4e,0x00,0x49,0x00,0x49,
                               0x00,0x2e,0x00,0x4c,0x00,0x4f,0x00,0x43,0x00,0x41,0x00,0x4c,0x00,0x05,0x00,0x14,
                               0x00,0x38,0x00,0x4e,0x00,0x49,0x00,0x49,0x00,0x2e,0x00,0x4c,0x00,0x4f,0x00,0x43,
                               0x00,0x41,0x00,0x4c,0x00,0x00,0x00,0x00,0x00};

    unsigned char buffer3[] = {0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
                               0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a,
                               0x04, 0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82,
                               0x08, 0x62, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
                               0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f};

    unsigned char buffer4[] = {0xa1, 0x82, 0x01, 0xfc, 0x30, 0x82, 0x01, 0xf8, 0xa2, 0x82, 0x01, 0xf4, 0x04, 0x82, 0x01, 0xf0,
                               0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00,
                               0x58, 0x00, 0x00, 0x00, 0x36, 0x01, 0x36, 0x01, 0x70, 0x00, 0x00, 0x00, 0x12, 0x00, 0x12, 0x00,
                               0xa6, 0x01, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x22, 0x00, 0x22, 0x00,
                               0xbe, 0x01, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x15, 0x82, 0x08, 0x62,
                               0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x01, 0x58, 0x1d, 0x5b, 0x64, 0x84, 0xbf, 0x86,
                               0x99, 0x09, 0x64, 0xe6, 0x49, 0x13, 0x08, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x1e, 0x69, 0xad, 0x14, 0x8b, 0x55, 0x9a, 0x1a, 0x34, 0xcb, 0x95, 0x26, 0x20, 0xc5, 0xc8, 0x36,
                               0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb6, 0x18, 0x72, 0x02, 0xcc, 0x8a, 0xdc, 0x01,
                               0xd0, 0x9c, 0xd6, 0x0b, 0x64, 0xff, 0x26, 0xd4, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x08, 0x00,
                               0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x01, 0x00, 0x1e, 0x00, 0x57, 0x00, 0x49, 0x00,
                               0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00, 0x34, 0x00, 0x55, 0x00, 0x4d, 0x00,
                               0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00, 0x04, 0x00, 0x34, 0x00, 0x57, 0x00,
                               0x49, 0x00, 0x4e, 0x00, 0x2d, 0x00, 0x31, 0x00, 0x46, 0x00, 0x58, 0x00, 0x34, 0x00, 0x55, 0x00,
                               0x4d, 0x00, 0x50, 0x00, 0x53, 0x00, 0x34, 0x00, 0x54, 0x00, 0x42, 0x00, 0x2e, 0x00, 0x38, 0x00,
                               0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00,
                               0x4c, 0x00, 0x03, 0x00, 0x14, 0x00, 0x38, 0x00, 0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00,
                               0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00, 0x4c, 0x00, 0x05, 0x00, 0x14, 0x00, 0x38, 0x00,
                               0x4e, 0x00, 0x49, 0x00, 0x49, 0x00, 0x2e, 0x00, 0x4c, 0x00, 0x4f, 0x00, 0x43, 0x00, 0x41, 0x00,
                               0x4c, 0x00, 0x08, 0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x09, 0x2b, 0x4f, 0x13, 0x3a, 0xc9, 0xcf, 0x9f, 0xb6,
                               0x47, 0xdc, 0x6c, 0xa6, 0x4f, 0x41, 0x8a, 0x12, 0xff, 0xb0, 0xa6, 0x57, 0xd2, 0xb9, 0x5b, 0xd6,
                               0x0d, 0x7f, 0xc9, 0xa2, 0xac, 0x8f, 0x0a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x24, 0x00, 0x63, 0x00,
                               0x69, 0x00, 0x66, 0x00, 0x73, 0x00, 0x2f, 0x00, 0x31, 0x00, 0x39, 0x00, 0x32, 0x00, 0x2e, 0x00,
                               0x31, 0x00, 0x36, 0x00, 0x38, 0x00, 0x2e, 0x00, 0x34, 0x00, 0x32, 0x00, 0x2e, 0x00, 0x32, 0x00,
                               0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00, 0x4f, 0x00, 0x52, 0x00, 0x4b, 0x00, 0x47, 0x00,
                               0x52, 0x00, 0x4f, 0x00, 0x55, 0x00, 0x50, 0x00, 0x61, 0x00, 0x31, 0x00, 0x34, 0x00, 0x4b, 0x00,
                               0x41, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x4c, 0x00, 0x49, 0x00, 0x4e, 0x00, 0x55, 0x00, 0x58, 0x00,
                               0x2d, 0x00, 0x32, 0x00, 0x30, 0x00, 0x32, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x32, 0x00,
                               0xd9, 0x34, 0x25, 0xe6, 0x04, 0x32, 0xc4, 0x60, 0xf2, 0x7e, 0x1c, 0xa5, 0x35, 0xbe, 0xf6, 0x22};
    
    asn1_obj *out;
    asn1_parser_error err = parse(buffer4, 512, &out);

    if (err < PARSER_OK) {
        printf("Error: 0x%x\n", err);
        return 1;
    }

    asn1_print(out, 0);

    free_asn1_obj(&out);

    printf("PARSER_OK\n");

    return 0;
}

#endif

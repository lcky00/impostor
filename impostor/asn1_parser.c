#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Base Types
#define ASN1_TYPE_EOC 0x00 // End of Content
#define ASN1_TYPE_BOOLEAN 0x01
#define ASN1_TYPE_INTEGER 0x02
#define ASN1_TYPE_BIT_STRING 0x03
#define ASN1_TYPE_OCTET_STRING 0x04
#define ASN1_TYPE_NULL 0x05
#define ASN1_TYPE_OBJECT_ID 0x06

#define ASN1_TYPE_OBJECT_DESCRIPTOR 0x07
#define ASN1_TYPE_REAL 0x09
#define ASN1_TYPE_RELATIVE_OID 0x0d
#define ASN1_TYPE_UTC_TIME 0x17
#define ASN1_TYPE_GENERALIZED_TIME 0x18

// Strings Types
#define ASN1_TYPE_UTF8_STRING 0x0c
#define ASN1_TYPE_UTF8_NUMERIC_STRING 0x12
#define ASN1_TYPE_PRINTABLE_STRING 0x13
#define ASN1_TYPE_T61_STRING 0x14
#define ASN1_TYPE_VIDEOTEX_STRING 0x15
#define ASN1_TYPE_IA5_STRING 0x16
#define ASN1_TYPE_GRAPHIC_STRING 0x19
#define ASN1_TYPE_VISIBLE_STRING 0x1a
#define ASN1_TYPE_GENERAL_STRING 0x1b
#define ASN1_TYPE_UNIVERSAL_STRING 0x1c
#define ASN1_TYPE_UNICODE_STRING 0x1e
#define ASN1_TYPE_CHARACTER_STRING 0x3d

// Construct Types
#define ASN1_TYPE_SEQUENCE 0x30
#define ASN1_TYPE_SET 0x31
#define ASN1_TYPE_ENUMERATED 0x0a
#define ASN1_TYPE_EXTERNAL 0x28
#define ASN1_TYPE_EMBEDDED_PDV 0x2b

// Tag GSSAPI
#define ASN1_TYPE_GSSAPI 0x60

// Tags NegotiationToken
#define ASN1_TYPE_SPNEGO_NEGTOKENINIT 0xa0
#define ASN1_TYPE_SPNEGO_NEGTOKENRESP 0xa1

// Tags NegTokenInit
#define ASN1_TYPE_SPNEGO_MECHTYPES 0xa0
#define ASN1_TYPE_SPNEGO_REQFLAGS 0xa1
#define ASN1_TYPE_SPNEGO_MECHTOKEN 0xa2
#define ASN1_TYPE_SPNEGO_MECHLISTMIC 0xa3

// Tags NegTokenResp
#define ASN1_TYPE_SPNEGO_NEGSTATE 0xa0
#define ASN1_TYPE_SPNEGO_SUPPORTEDMECH 0xa1
#define ASN1_TYPE_SPNEGO_RESPONSETOKEN 0xa2
#define ASN1_TYPE_SPNEGO_MECHLISTMIC 0xa3

/** La sintassi di trasferimento usata dalle regole di codifica distinte segue sempre 
 * un formato tag, lunghezza, valore. Il formato viene in genere definito triplo TLV.
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
 * Il campo lunghezza in un triplo TLV identifica il numero di byte codificati nel 
 * campo valore. Il campo Valore contiene il contenuto inviato tra computer. 
 * Se il campo valore contiene meno di 128 byte, il campo lunghezza richiede un solo 
 * byte. Il bit 7 del campo lunghezza è zero (0) e i bit rimanenti identificano il numero 
 * di byte di contenuto inviati. 
 * Se il campo valore contiene più di 127 byte, il bit 7 del campo lunghezza è uno (1) 
 * e i bit rimanenti identificano il numero di byte necessari per contenere la lunghezza. 
 * Gli esempi sono illustrati nella figura seguente.
 * 
 * |0|0|1|1|0|1|0|0||x|x|x|x|x|x|x|x|x|x|x|x|x|x|...
 *  ^ ^-----------^  ^--------------------------^ 
 *  |  Length = 52           Value -> 52 Bytes
 *  |    
 * Bit per 0<=Length <= 127 bytes
 * 
 * |1|0|0|0|0|0|1|0||0|0|0|1|0|0|1|1|0|1|0|0|0|1|1|0||x|x|x|x|x|x|x|x|...
 *  ^ ^-----------^  ^-----------------------------^  ^---------------^
 *  | Num Of len = 2       2 Bytes -> 4934			     Value -> 4934 Bytes										
 *  |    
 * Bit per 128 <= Length <= 256^126 bytes
 * 
 */

/* Mask per capire dal bit più significativo del primo byte se la len >= 128 */
#define PARSER_CHECK_LEN_BYTE_MASK 0x80             // 1000 0000
#define PARSER_EXTRACT_LEN_FROM_BYTES_MASK 0x7F     // 0111 1111

/* Dimesioni per lunghezza TLV */
#define PARSER_MAX_LEN_LEN_BYTES 0x8                // 8 bytes
#define PARSER_MAX_LEN_VALUE_BYTES 0x7F             // 127 

/* Dimesione di inzio per lista di asn1_obj */
#define PARSER_INIT_DIM_LIST_ASN1_OBJ 100
#define PARSER_MAX_DIM_LIST_ASN1_OBJ 400
#define PARSER_MAX_ENTRY_VALUE_LEN (16 * 1024 * 1024) // 16 MB

#define PARSER_INIT_DIM_STACK_FREE 100

/**************************************************/
//                    ERRORS
/*************************************************/

#define PARSER_OK 0x00000000
#define PARSER_ERROR_LEN_LEN_BYTES_TOO_BIG 0x80000001
#define PARSER_ERROR_LEN_LEN_OVERFLOW 0x80000002
#define PARSER_ERROR_INVALID_BUFFER 0x80000003
#define PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT 0x80000004
#define PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY 0x80000005
#define PARSER_ERROR_ALLOC_NEW_ASN1_ENTRY_VALUE 0x80000006
#define PARSER_ERROR_INVALID_BLOB 0x80000007
#define PARSER_ERROR_ASN1_ENTRY_VALUE_LEN_TOO_BIG 0x80000008
#define PARSER_ERROR_FREE_STACK_ALLOC 0x80000009
#define PARSER_ERROR_FREE_STACK_REALLOC 0x8000000a
#define PARSER_ERROR_INVALID_ENTRY 0x8000000b
#define PARSER_ERROR_APPEND_INVALID_OBJ 0x8000000c
#define PARSER_ERROR_APPEND_REALLOC 0x8000000d
#define PARSER_ERROR_APPEND_REALLOC_MAX_CHILD_REACHED 0x8000000e

typedef uint32_t asn1_parser_error;

/**************************************************/
//                    Struct
/**************************************************/

typedef struct asn1_entry {
    size_t len;
    uint8_t *value;
} asn1_entry;

typedef struct asn1_obj {
    uint8_t type;
    struct asn1_entry *entry;
    size_t len;
    size_t dim;
    struct asn1_obj **list;
} asn1_obj;

/* Struct for call stack */
typedef struct parser_call_stack {
    
} parser_call_stack;


/**************************************************/
//                  PARSING UTILS
/**************************************************/

uint8_t is_base_type(uint8_t type) {
    return (type == ASN1_TYPE_INTEGER || type == ASN1_TYPE_BOOLEAN
        || type == ASN1_TYPE_BIT_STRING || type == ASN1_TYPE_OCTET_STRING
        || type == ASN1_TYPE_NULL || type == ASN1_TYPE_OBJECT_ID 
        || type == ASN1_TYPE_UTF8_STRING || type == ASN1_TYPE_UNICODE_STRING
        || type == ASN1_TYPE_IA5_STRING || type == ASN1_TYPE_PRINTABLE_STRING) ? 1: 0;

}

asn1_entry * new_asn1_entry() {
    asn1_entry * entry = malloc(sizeof(struct asn1_entry));

    if (!entry) return NULL;

    entry->len = 0;
    entry->value = NULL;

    return entry;
}

asn1_obj * new_asn1_obj() {
    asn1_obj * obj = malloc(sizeof(struct asn1_obj));

    if (!obj) return NULL;

    obj->type = 0;
    obj->entry = NULL;
    obj->len = 0;
    obj->dim = PARSER_INIT_DIM_LIST_ASN1_OBJ;
    obj->list = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_LIST_ASN1_OBJ);

    if (!obj->list) {
        free(obj);
        return NULL;
    }

    memset(obj->list, 0, sizeof(struct asn1_obj *) * PARSER_INIT_DIM_LIST_ASN1_OBJ);
    
    return obj;
}

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

void free_asn1_entry(asn1_entry **entry) {
    if (!entry || !*entry) return;

    if ((*entry)->value) {
        free((*entry)->value);
        (*entry)->value = NULL;
    }

    free(*entry);
    *entry = NULL;
}

asn1_parser_error free_asn1_obj(asn1_obj **obj) {
    if (!obj || !*obj) return PARSER_OK;

    size_t stack_top = 0;
    size_t stack_cap = PARSER_INIT_DIM_STACK_FREE;
    asn1_obj **stack = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_STACK_FREE);

    if (!stack) return PARSER_ERROR_FREE_STACK_ALLOC;

    stack[stack_top++] = *obj;

    while (stack_top > 0) {
        asn1_obj *act_obj = stack[stack_top - 1];

        if (act_obj->list) {
            for (size_t i = 0; i < act_obj->len; i++) {
                if (stack_top == stack_cap) {
                    asn1_obj **tmp = realloc(stack, sizeof(struct asn1_obj *) * (stack_cap * 2));
                    if (!tmp) {
                        while (stack_top > 0) {
                            asn1_obj *o = stack[--stack_top];
                            free_asn1_entry(&o->entry);
                            free(o);
                        }
                        free(stack);
                        return PARSER_ERROR_FREE_STACK_REALLOC;
                    }
                    stack = tmp;
                    stack_cap *= 2;
                }
                stack[stack_top++] = act_obj->list[i];
            }
            free(act_obj->list);
            act_obj->list = NULL;
            act_obj->len = 0;
            continue;
        }

        free_asn1_entry(&act_obj->entry);
        free(act_obj);

        stack_top--;
    }    
    free(stack);
    *obj = NULL;
    return PARSER_OK;
}

/**************************************************/
//             PARSING PER LUNGHEZZE
/**************************************************/

/** Funzione che dato il byte della lunghezza ritorna:
 *  0 : se il primo bit è zero. len <= 127
 *  1 : se il primo bit è uno. len >= 128
 */
uint8_t check_long_form(uint8_t b) {
    return b & PARSER_CHECK_LEN_BYTE_MASK;
}

uint8_t extract_len_short_form(uint8_t b) {
    return b & PARSER_EXTRACT_LEN_FROM_BYTES_MASK;
}

/**
 * Estrae lunghezza di V in TLV. Controlla che i bytes non siano maggiori di 8.
 * Perchè altrimenti significa che abbiamo una lunghezza magiore di 64 bit unsigned,
 * e non possiamo memorizzarla. 64 bit comunque è una scelta ragionevole, in quanto 
 * possiamo avere un V che ha potenzialmente 2^64-1 bytes, chè risulta ragionevole anche
 * per dati riguardanti crittografia (rsa, ecc) che hanno blob non standard.
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

asn1_parser_error parse_length(uint8_t *buffer, uint64_t *out_len, uint64_t *num_bytes_len) {
    if (!buffer || !out_len || !num_bytes_len) return PARSER_ERROR_INVALID_BUFFER;

    uint8_t is_long_form = check_long_form(*(buffer));
    uint64_t b = extract_len_short_form(*(buffer)); // Per ottenere lunghezza bytes
    *num_bytes_len = 1;
    if (is_long_form) {
        uint64_t b_aux;
        int32_t res = extract_len_long_form(buffer + 1, b, &b_aux);
        
        if (res < PARSER_OK) return res;
        b = b_aux;
        *num_bytes_len = b;
    }
    
    *out_len = b;
    return PARSER_OK;
}

/**************************************************/
//              PARSING TYPES
/**************************************************/

asn1_entry * parse_asn1_integer() {};
asn1_entry * parse_asn1_boolean() {};
asn1_entry * parse_asn1_bit_string() {};
asn1_entry * parse_asn1_octet_string() {};
asn1_entry * parse_asn1_null() {};
asn1_entry * parse_asn1_object_id() {};
asn1_entry * parse_asn1_unicode_string() {};
asn1_entry * parse_asn1_ia5_string() {};
asn1_entry * parse_asn1_printable_string() {};
asn1_entry * parse_asn1_utf8_string() {};

asn1_parser_error parse_blob(const uint8_t *blob, size_t len, asn1_entry **entry) {
    if (!entry) return PARSER_ERROR_INVALID_ENTRY;

    if (!blob) {
        *entry = NULL;
        return PARSER_ERROR_INVALID_BLOB;
    }

    if (len > PARSER_MAX_ENTRY_VALUE_LEN) {
        *entry = NULL;
        return PARSER_ERROR_ASN1_ENTRY_VALUE_LEN_TOO_BIG;
    }

    *entry = new_asn1_entry();

    if (!entry) {
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
//                 MAIN PARSER
/**************************************************/

asn1_obj * parse(uint8_t * buffer, size_t len, size_t * ret_len, asn1_parser_error *err) {
    
}



int main() {

    unsigned char buffer[] = {0x30, 0x23, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x03,
                              0x13, 0x06, 0x54, 0x65, 0x73, 0x74, 0x43, 0x4e, 0x31, 0x10, 0x30,
                              0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x07, 0x54, 0x65, 0x73,
                              0x74, 0x4f, 0x72, 0x67};
                        
    //parse(buffer, 37);
    
    //printf("%d\n", sizeof(size_t));
    //printf("%d\n", get_length(buffer+1, 2));
    
    uint64_t b, o;
    int32_t r = parse_length(buffer + 1, &b, &o);

    printf("Return: 0x%x\n", r);

    printf("%lld, %lld\n", b,o);
    


}

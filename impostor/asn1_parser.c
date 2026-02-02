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

/* Mask per capire dal bit più significativo del primo byte se la len >= 128 */
#define PARSER_CHECK_LEN_BYTE_MASK 0x80             // 1000 0000
#define PARSER_EXTRACT_LEN_FROM_BYTES_MASK 0x7F     // 0111 1111

/* Dimesioni per lunghezza TLV */
#define PARSER_MAX_LEN_LEN_BYTES 8                // 8 bytes
#define PARSER_MAX_LEN_VALUE_BYTES 127            // 127 

/* Dimesione di inzio per lista di asn1_obj */
#define PARSER_INIT_DIM_LIST_ASN1_OBJ 100
#define PARSER_MAX_DIM_LIST_ASN1_OBJ 400
#define PARSER_MAX_ENTRY_VALUE_LEN (16 * 1024 * 1024) // 16 MB

#define PARSER_INIT_DIM_STACK 100
#define PARSER_MAX_DIM_STACK 800

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
#define PARSER_ERROR_FREE_ASN1_OBJ_ALLOC 0x80000009
#define PARSER_ERROR_FREE_ASN1_OBJ_REALLOC 0x8000000a
#define PARSER_ERROR_INVALID_ENTRY 0x8000000b
#define PARSER_ERROR_APPEND_INVALID_OBJ 0x8000000c
#define PARSER_ERROR_APPEND_REALLOC 0x8000000d
#define PARSER_ERROR_APPEND_REALLOC_MAX_CHILD_REACHED 0x8000000e

#define PARSER_ERROR_STACK_INVALID_STACK 0x8000000f
#define PARSER_ERROR_STACK_MAX_DIM_EXCEEDED 0x80000010
#define PARSER_ERROR_STACK_LEN_DIM_EXCEEDED 0x80000011
#define PARSER_ERROR_STACK_REALLOC 0x80000012
#define PARSER_ERROR_STACK_POP_FROM_EMPTY_STACK 0x80000013
#define PARSER_ERROR_STACK_TOP_FROM_EMPTY_STACK 0x80000014
#define PARSER_ERROR_STACK_ALLOCATION 0x80000015
#define PARSER_ERROR_STACK_ENTRY_ALLOCATION 0x80000016
#define PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL 0x80000017
#define PARSER_ERROR_STACK_PUSH_ENTRY_IS_NULL 0x80000018


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

/**************************************************/
//                 PARSER OBJECT 
/**************************************************/

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
    size_t stack_cap = PARSER_INIT_DIM_STACK;
    asn1_obj **stack = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_STACK);

    if (!stack) return PARSER_ERROR_FREE_ASN1_OBJ_ALLOC;

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
                        return PARSER_ERROR_FREE_ASN1_OBJ_REALLOC;
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
        *num_bytes_len += b;
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
//                STACK UTILS
/**************************************************/

/* Struct for call stack */
typedef struct parser_stack_entry {
    asn1_obj *parent;
    asn1_obj *obj;
    size_t ret_len;
    size_t effective_len;  
    size_t offset;  
    size_t num_bytes_len;
} parser_stack_entry;

typedef struct parser_stack {
    size_t dim;
    size_t len;
    parser_stack_entry **stack;
} parser_stack;

parser_stack_entry * new_parser_stack_entry() {
    parser_stack_entry * entry = malloc(sizeof(struct parser_stack_entry));

    if (!entry) return NULL;

    entry->parent = NULL;
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
    if (!stack) return 0;
    return stack->len > 0 ? 1 : 0;
}

/** Non Libera obj e parent, ma annulla i puntatori. Perchè
 * gli oggetti veri e propri appartengono a asn1_obj che è la 
 * struttura parsata.
 * Sarà una free a asn1_obj a liberarli.
 */
void free_parser_stack_entry(parser_stack_entry **entry) {
    if (!entry || !*entry) return;

    (*entry)->obj = NULL;
    (*entry)->parent = NULL;

    free(*entry);
    *entry = NULL;
}

/** Fa una free dello stack utilizzato per il parsing.
 * Non l'ibera gli oggetti asn1_obj.
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
}

/**
 * Realloc dello stack. Se fallisce non cambia stato ma ritorna errore.
 * Liberare la memoria spetta al chiamante.
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
 * Pusha nello stack. Rialloca in automatico in caso di necessità. Se push fallisce ritorna errore.
 * Liberare la memoria spetta al chiamante.
 */
asn1_parser_error parser_stack_push(parser_stack *stack, parser_stack_entry *entry) {
    if (!stack || !entry || !stack->stack) return PARSER_ERROR_STACK_INVALID_STACK;

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
 * Poppa dallo stack. Non Libera la entry dello stack e la ritorna. se NULL fa solo pop 
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
//                PARSER UTILS
/**************************************************/

uint8_t is_base_type(uint8_t type) {
    return (type == ASN1_TYPE_INTEGER || type == ASN1_TYPE_BOOLEAN
        || type == ASN1_TYPE_BIT_STRING || type == ASN1_TYPE_OCTET_STRING
        || type == ASN1_TYPE_NULL || type == ASN1_TYPE_OBJECT_ID 
        || type == ASN1_TYPE_UTF8_STRING || type == ASN1_TYPE_UNICODE_STRING
        || type == ASN1_TYPE_IA5_STRING || type == ASN1_TYPE_PRINTABLE_STRING) ? 1: 0;

}

/**************************************************/
//                MAIN PARSER
/**************************************************/

asn1_parser_error parse(uint8_t *buffer, size_t len, asn1_obj **obj_out) {
    // TODO: Vedere un Check per len
    asn1_parser_error res;

    if (!buffer || !obj_out) return PARSER_ERROR_INVALID_BUFFER;

    // Creazione oggetto "root"
    asn1_obj *obj = new_asn1_obj();
    if (!obj) return PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT;

    uint64_t act_len, num_bytes;
    res = parse_length(buffer + 1, &act_len, &num_bytes);
    if (res < PARSER_OK) {
        free_asn1_obj(&obj);
        return res;
    }

    uint8_t type = *buffer;
    obj->type = type;
    obj->entry = NULL;

    // Verifico se obj è una leaf
    if (is_base_type(type)) {
        // Creazione entry oggetto. Estraggo blob e creo entry da mettere in obj
        asn1_entry *entry;
        res = parse_blob(buffer + 1 + num_bytes, act_len, &entry);
        if (res < PARSER_OK) {
            free_asn1_obj(&obj);
            return res;
        }
        obj->entry = entry;
        *obj_out = obj;
        return PARSER_OK;
    }

    // NON è una leaf. Creiamo stack, pushamo dentro entry.
    parser_stack *stack = new_parser_stack();
    if (!stack) {
        free_asn1_obj(obj);
        return PARSER_ERROR_STACK_ALLOCATION;
    }

    parser_stack_entry *stack_entry = new_parser_stack_entry();
    if (!stack_entry) {
        free_parser_stack(&stack);
        free_asn1_obj(obj);
        return PARSER_ERROR_STACK_ENTRY_ALLOCATION;
    }

    stack_entry->obj = obj;
    stack_entry->parent = NULL;
    stack_entry->effective_len = 1 + num_bytes + act_len;
    stack_entry->num_bytes_len = num_bytes;
    stack_entry->offset = 0;
    stack_entry->ret_len = 0;

    res = parser_stack_push(stack, stack_entry);
    if (res < PARSER_OK) {
        free_parser_stack(&stack);
        free_asn1_obj(obj);
        return res;
    }

    while (!parser_stack_is_empty(stack)) {
        parser_stack_entry *tmp_stack_entry;
        res = parser_stack_top(stack, &tmp_stack_entry);
        if (res < PARSER_OK) {
            free_parser_stack(&stack);
            free_asn1_obj(obj);
            return res;
        }

        // Controllo per vedere se l'onj dell'entry dello stack è NULL
        if (!tmp_stack_entry->obj) {
            free_parser_stack(&stack);
            free_asn1_obj(obj);
            return PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL;
        }

        // E' di tipo "root"
        if (!is_base_type(tmp_stack_entry->obj->type)) {
            
            if (tmp_stack_entry->ret_len == (tmp_stack_entry->effective_len - 1 - tmp_stack_entry->num_bytes_len)) {
                res = parser_stack_pop(stack, NULL);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(obj);
                    return res;
                }
            }
            else {
                type = buffer + tmp_stack_entry->offset + 1 + tmp_stack_entry->num_bytes_len + tmp_stack_entry->ret_len;

                asn1_obj * tmp_obj = new_asn1_obj;
                if (!tmp_obj) {
                    free_parser_stack(&stack);
                    free_asn1_obj(obj);
                    return PARSER_ERROR_ALLOC_NEW_ASN1_OBJECT;
                }

                tmp_obj->type = type;
                tmp_obj->entry = NULL;

                parser_stack_entry *new_tmp_stack_entry = new_parser_stack_entry();
                if (!new_tmp_stack_entry) {
                    free_parser_stack(&stack);
                    free_asn1_obj(obj);
                    return PARSER_ERROR_STACK_ENTRY_ALLOCATION;
                }

                // TODO: estrarre lunghezze
                new_tmp_stack_entry->

            }
        }

        // E' di tipo "leaf"
        else {

        }
    }

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

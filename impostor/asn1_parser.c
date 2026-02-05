#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/**************************************************/
//                  CONSTANTS
/*************************************************/

/* Mask per capire dal bit più significativo del primo byte se la len >= 128 */
#define PARSER_CHECK_LEN_BYTE_MASK              0x80         // 1000 0000
#define PARSER_EXTRACT_LEN_FROM_BYTES_MASK      0x7F         // 0111 1111

/* Dimesioni per lunghezza TLV */
#define PARSER_MAX_LEN_LEN_BYTES                8             // 8 bytes
#define PARSER_MAX_LEN_VALUE_BYTES              127           // 127 

/* Dimesioni di inizializzazione e limiti massimi */
#define PARSER_INIT_DIM_LIST_ASN1_OBJ           100
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
#define ASN1_TYPE_SPNEGO_MECHTYPES          0xa0
#define ASN1_TYPE_SPNEGO_REQFLAGS           0xa1
#define ASN1_TYPE_SPNEGO_MECHTOKEN          0xa2

// Tags NegTokenResp
#define ASN1_TYPE_SPNEGO_NEGSTATE           0xa0
#define ASN1_TYPE_SPNEGO_SUPPORTEDMECH      0xa1
#define ASN1_TYPE_SPNEGO_RESPONSETOKEN      0xa2
#define ASN1_TYPE_SPNEGO_MECHLISTMIC        0xa3

typedef uint8_t asn1_type_t;

#define LEAF_NODE 0x00
#define ROOT_NODE 0x01

/**
 * Struttura per la gestione dei tipi. Con relativo nome, limite, tipo nodo (root o leaf)
 * utile per la creazione dell'albero in fase di parsing, e errore eventuale per 
 * superamento limite.
 */
typedef struct types_info {
    asn1_type_t type;
    const char *name;
    size_t max_len;
    uint8_t flag;
    asn1_parser_error err;
} types_info;

// "Tabella" dei tipi. Array di types_info.
const types_info tags[] = {
    // Base Types
    {ASN1_TYPE_EOC,                     "ASN1_TYPE_EOC",                   PARSER_MAX_ASN1_EOC_SIZE,                0, PARSER_ERROR_MAX_ASN1_EOC_SIZE},
    {ASN1_TYPE_BOOLEAN,                 "ASN1_TYPE_BOOLEAN",               PARSER_MAX_ASN1_BOOLEAN_SIZE,            0, PARSER_ERROR_MAX_ASN1_BOOLEAN_SIZE},
    {ASN1_TYPE_INTEGER,                 "ASN1_TYPE_INTEGER",               PARSER_MAX_ASN1_NUMERIC_SIZE,            0, PARSER_ERROR_MAX_ASN1_NUMERIC_SIZE},
    {ASN1_TYPE_BIT_STRING,              "ASN1_TYPE_BIT_STRING",            PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_OCTET_STRING,            "ASN1_TYPE_OCTET_STRING",          PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},
    {ASN1_TYPE_NULL,                    "ASN1_TYPE_NULL",                  PARSER_MAX_ASN1_NULL_SIZE,               0, PARSER_ERROR_MAX_ASN1_NULL_SIZE},
    {ASN1_TYPE_OBJECT_ID,               "ASN1_TYPE_OBJECT_ID",             PARSER_MAX_ASN1_OID,                     0, PARSER_ERROR_MAX_ASN1_OID_SIZE},

    {ASN1_TYPE_OBJECT_DESCRIPTOR,       "ASN1_TYPE_OBJECT_DESCRIPTOR",     PARSER_MAX_ASN1_STRING_SIZE,             0, PARSER_ERROR_MAX_ASN1_STRING_SIZE},  // Contiene solo caratteri ASCII leggibili.
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
    {ASN1_TYPE_SPNEGO_MECHTYPES,        "ASN1_TYPE_SPNEGO_MECHTYPES",      PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_REQFLAGS,         "ASN1_TYPE_SPNEGO_REQFLAGS",       PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_MECHTOKEN,        "ASN1_TYPE_SPNEGO_MECHTOKEN",      PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    
    // Tags NegTokenResp
    {ASN1_TYPE_SPNEGO_NEGSTATE,         "ASN1_TYPE_SPNEGO_NEGSTATE",       PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_SUPPORTEDMECH,    "ASN1_TYPE_SPNEGO_SUPPORTEDMECH",  PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_RESPONSETOKEN,    "ASN1_TYPE_SPNEGO_RESPONSETOKEN",  PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE},
    {ASN1_TYPE_SPNEGO_MECHLISTMIC,      "ASN1_TYPE_SPNEGO_MECHLISTMIC",    PARSER_MAX_ASN1_DEFAULT,     1, PARSER_ERROR_MAX_ASN1_CONSTRUCTED_TYPE_SIZE}
};

#define TAGS_SIZE (sizeof(tags) / sizeof(tags[0]))

/**************************************************/
//                    Struct
/**************************************************/

// Eventuale valore del nodo ASN.1 nell'albero ASN.1 
//risualtato del parsing.
typedef struct asn1_entry {
    size_t len;
    uint8_t *value;
} asn1_entry;

// Nodo dell'albero ASN.1 
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

/**
 * Funzione di utility per ottenere, dato un type, la sua entry
 * nella tabella tags.
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
 * Funzione di utility per determinare se un type è di tipo "root"
 * nell'albero ASN.1.
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
 * Funzione che verifica se una lunghezza, dato un offset e una lunghezza massima
 * del blob, è sicura. Nel senso che verifica che non sia maggiore della lunghezza massima,
 * partendo da un offset. Verifica inoltre che l'offset non sia maggiore di max_len
 * per un controllo più safe.
 */
uint8_t is_safe_asn1_length(size_t len, size_t offset, size_t max_len) {
    return offset <= max_len && len <= max_len - offset;
}

/**
 * Funzione che dato un type e una lunghezza verifica che la lunghezza
 * ripestti i limiti peril respettivo type. Fa un lookup nella tabella "tags".
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
 * Crea una entry. Una entry fa parte della struttura asn1_obj 
 * che è un nodo dell'albero ASN.1. Un nodo asn_obj avrà una entry
 * se è un nodo di tipo leaf.
 */
asn1_entry * new_asn1_entry() {
    asn1_entry * entry = malloc(sizeof(struct asn1_entry));

    if (!entry) return NULL;

    entry->len = 0;
    entry->value = NULL;

    return entry;
}

/**
 * Crea un asn1_obj, che è un nodo dell'albero ASN.1.
 * Ogni nodo di tipo "root" avrà una lista di child.
 */
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

/**
 * Appende a list di un nodo di tipo "root".
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
 * Libera una asn1_entry.
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
 * Libera tutto un albero ASN.1 comprese le entry dei nodi root.
 * Usa uno stack per memorizzare ogni nodo e liberarlo.
 */
asn1_parser_error free_asn1_obj(asn1_obj **obj) {
    if (!obj || !*obj) return PARSER_OK;

    // Punta alla cima dello stack
    size_t stack_top = 0;
    // Capacità inziale dello stack
    size_t stack_cap = PARSER_INIT_DIM_STACK;
    asn1_obj **stack = malloc(sizeof(struct asn1_obj *) * PARSER_INIT_DIM_STACK);

    if (!stack) return PARSER_ERROR_FREE_ASN1_OBJ_ALLOC;

    // Mettiamo nello stack il nodo radice dell'albero
    stack[stack_top++] = *obj;

    while (stack_top > 0) {
        // Facciamo una top dallo stack per prendere il primo elemento
        asn1_obj *act_obj = stack[stack_top - 1];

        // Se ha una lista piena procediamo a liberare i figli
        if (act_obj->list) {
            for (size_t i = 0; i < act_obj->len; i++) {
                // Per ogni figlio andiamo a pusharlo nelo stack
                // Se necessario lo stack viene riallocato per espandere la sua memoria
                if (stack_top == stack_cap) {
                    asn1_obj **tmp = realloc(stack, sizeof(struct asn1_obj *) * (stack_cap * 2));

                    // Se la riallocazione fallisce dobbiamo procedere a liberare tutto lo stack
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
                // Pushamo nello stack il figlio
                stack[stack_top++] = act_obj->list[i];
            }

            // Una volta che tutti i figli sono stati pushati liberiamo list e
            // riprendiamo dall'inzio
            free(act_obj->list);
            act_obj->list = NULL;
            act_obj->len = 0;
            continue;
        }

        // Se non ha lista significa che è una leaf oppure un nodo precedentemente
        // Liberato dalla lista.
        // Quindi procediamo a liberare la entry se la ha e fare un pop dallo stack e liberare il nodo
        free_asn1_entry(&act_obj->entry);
        free(act_obj);

        stack_top--;
    }
    
    // Lo stack è vuoto quindi tutto è stato liberato 
    // oppure non c'era nulla da liberare.
    // Liberiamo puntatore stack.
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

/**
 * Funzione che dato un byte estare con una bitmask il valore.
 * Serve per estrarre valore lunghezza in short-form o lunghezza dei byte
 * per long-form.
 */
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

/**
 * Funzione che dato un puntatore al buffer nella posizione utile per estarre la 
 * lunghezza, estrare lughezza di value in byte, e il numero di byte che descrivono la lunghezza.
 */
asn1_parser_error parse_length(uint8_t *buffer, uint64_t *out_len, uint64_t *num_bytes_len) {
    if (!buffer || !out_len || !num_bytes_len) return PARSER_ERROR_INVALID_BUFFER;

    uint8_t is_long_form = check_long_form(*(buffer));
    uint64_t b = extract_len_short_form(*(buffer)); // Per ottenere lunghezza bytes
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
 * Funzione che dato un type, un blob (puntatore a buffer nella poszione utile) e una lunghezza,
 * ritorna una asn1_entry con il contenuto "grezzo" del buffer. La entry avrà lunghezza in byte
 * del contenuto grezzo e un buffer contenente il contenuto grezzo.
 * Utile poi per fare un interpetazione dei valori con funzioni apposite. Es valutare Integer, STRING ecc.
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

/**
 * Struttura che desscrive una entry per lo stack utilizzato 
 * per il main parser.
 */
typedef struct parser_stack_entry {
    asn1_obj *parent;
    asn1_obj *obj;
    size_t ret_len;
    size_t effective_len;  
    size_t offset;  
    size_t num_bytes_len;
    uint8_t is_base_stack;
} parser_stack_entry;

/**
 * Struttura delo stack per main parser
 */
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
    entry->is_base_stack = 0;
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
//                MAIN PARSER
/**************************************************/

asn1_parser_error parse(uint8_t *buffer, size_t len, asn1_obj **obj_out) {
    if (len > PARSER_MAX_ASN1_SIZE) return PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG;

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

    if (!is_safe_asn1_length(act_len, 0, len)) {
        free_asn1_obj(&obj);
        return PARSER_ERROR_ASN1_BLOB_LEN_TOO_BIG;
    }

    asn1_type_t type = *buffer;

    if (!is_valid_type(type)) {
        free_asn1_obj(&obj);
        return PARSER_ERROR_INVALID_TAG;
    }

    obj->type = type;
    obj->entry = NULL;

    // Verifico se obj è una leaf
    uint8_t is_root;
    res = is_root_node(type, &is_root);
    if (res < PARSER_OK) {
        free_asn1_obj(&obj);
        return res;
    }
    // Verifico se obj è una leaf
    if (!is_root) {
        // Creazione entry oggetto. Estraggo blob e creo entry da mettere in obj
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

    // NON è una leaf. Creiamo stack, pushamo dentro entry.
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
    stack_entry->parent = NULL;
    stack_entry->effective_len = 1 + num_bytes + act_len;
    stack_entry->num_bytes_len = num_bytes;
    stack_entry->offset = 0;
    stack_entry->ret_len = 0;
    stack_entry->is_base_stack = 1;

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

        // Controllo per vedere se l'obj dell'entry dello stack è NULL
        if (!tmp_stack_entry->obj) {
            free_parser_stack(&stack);
            free_asn1_obj(&obj);
            return PARSER_ERROR_STACK_ENTRY_OBJ_IS_NULL;
        }

        printf("----------------------\n");
        printf("TOP dallo Stack:\n Tag: 0x%x\n", tmp_stack_entry->obj->type);

        // E' di tipo "root"
        res = is_root_node(tmp_stack_entry->obj->type, &is_root);
        if (res < PARSER_OK) {
            free_parser_stack(&stack);
            free_asn1_obj(&obj);
            return res;
        }
        if (is_root) {
            printf("E' di tipo \"root\".\n");
            printf("effective_len: %d\n", tmp_stack_entry->effective_len);
            printf("num_bytes_len: %d\n", tmp_stack_entry->num_bytes_len);
            printf("offset: %d\n", tmp_stack_entry->offset);
            printf("ret_len: %d\n", tmp_stack_entry->ret_len);

            if (tmp_stack_entry->ret_len >= (tmp_stack_entry->effective_len - 1 - tmp_stack_entry->num_bytes_len)) {
                size_t temp_eff_len = tmp_stack_entry->effective_len;
                res = parser_stack_pop(stack, NULL);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return res;
                }
                
                // Modifico ret_len parent
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

                asn1_obj * tmp_obj = new_asn1_obj();
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
                new_tmp_stack_entry->parent = tmp_stack_entry->obj;
                new_tmp_stack_entry->offset = tmp_stack_entry->offset 
                                                + 1 + tmp_stack_entry->num_bytes_len 
                                                + tmp_stack_entry->ret_len;
                new_tmp_stack_entry->num_bytes_len = num_bytes;
                new_tmp_stack_entry->effective_len = 1 + num_bytes + act_len;
                new_tmp_stack_entry->ret_len = 0;

                // Appendiamo alla lista del padre
                if (!tmp_stack_entry->is_base_stack) {
                    res = append_asn1_obj_list(&tmp_stack_entry->parent, tmp_obj);
                    if (res < PARSER_OK) {
                        free_parser_stack(&stack);
                        free_asn1_obj(&obj);
                        free_asn1_obj(&tmp_obj);
                        free_parser_stack_entry(&new_tmp_stack_entry);
                        return res;
                    }
                }

                // Push nello stack della entry
                res = parser_stack_push(stack, new_tmp_stack_entry);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    free_parser_stack_entry(&new_tmp_stack_entry);
                    return res;
                }
            }
        }

        // E' di tipo "leaf"
        else {
            printf("E' di tipo \"leaf\".\n");
            printf("effective_len: %d\n", tmp_stack_entry->effective_len);
            printf("num_bytes_len: %d\n", tmp_stack_entry->num_bytes_len);
            printf("offset: %d\n", tmp_stack_entry->offset);
            printf("ret_len: %d\n", tmp_stack_entry->ret_len);
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
            // append in parent
            res = append_asn1_obj_list(&tmp_stack_entry->parent, tmp_stack_entry->obj);
            if (res < PARSER_OK) {
                free_parser_stack(&stack);
                free_asn1_obj(&obj);
                free_asn1_entry(&obj_entry);
                return res;
            }

            // Essendo una leaf facciamo una free di list
            if (tmp_stack_entry->obj->list) {
                free(tmp_stack_entry->obj->list);
                tmp_stack_entry->obj->dim = 0;
                tmp_stack_entry->obj->list = NULL;
            }

            size_t ret_len_aux = tmp_stack_entry->effective_len;

            // Pop della leaf
            res = parser_stack_pop(stack, NULL);
            if (res < PARSER_OK) {
                free_parser_stack(&stack);
                free_asn1_obj(&obj);
                return res;
            }

            // Modifico ret_len parent
            if (!parser_stack_is_empty(stack)) {
                parser_stack_entry *top_stack_entry;
                res = parser_stack_top(stack, &top_stack_entry);
                if (res < PARSER_OK) {
                    free_parser_stack(&stack);
                    free_asn1_obj(&obj);
                    return res;
                }

                // Modifico ret_len parent
                top_stack_entry->ret_len += ret_len_aux;
            }
        }
    }

    *obj_out = obj;
    free_parser_stack(&stack);
    return PARSER_OK;
}



int main() {

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
    
    asn1_obj *out;
    asn1_parser_error err = parse(buffer2, 249, &out);

    if (err < PARSER_OK) {
        printf("Error: 0x%x\n", err);
        return 1;
    }

    free_asn1_obj(&out);

    return 0;
}

#include <stdint.h>
#include <stdlib.h>

#include "asn1_parser.h"

#define SPNEGO_OK                           0x00000000
#define SPNEGO_DEC_ERR_INVALID_ASN1_TREE    0x80000001
#define SPNEGO_DEC_ERR_INVALID_OID          0x80000002
#define SPNEGO_DEC_ERR_UNEXPECTED_TAG       0x80000003
#define SPNEGO_DEC_ERR_ALLOC                0x80000004
#define SPNEGO_DEC_ERR_INVALID_ARG          0x80000005
#define SPNEGO_DEC_ERR_INVALID_ASN1_NODE    0x80000006

typedef int32_t spnego_dec_error_t;

#define SPNEGO_INIT_TAG 0xa0
#define SPNEGO_RESP_TAG 0xa1

#define SPNEGO_INIT_MECHTYPES   0xa0
#define SPNEGO_INIT_REFLAGS     0xa1
#define SPNEGO_INIT_MECHTOKEN   0xa2
#define SPNEGO_INIT_NEGHINTS    0xa3
#define SPNEGO_INIT_MECHLISTMIC 0xa4

#define SPNEGO_RESP_NEGSTATE        0xa0
#define SPNEGO_RESP_SUPORTED_MECH   0xa1
#define SPNEGO_RESP_RESPONSE_TOKEN  0xa2
#define SPNEGO_RESP_MECH_LIST_MIC   0xa3


#define ASN1_SEQUENCE       0x30
#define ASN1_AID            0x60
#define ASN1_OID            0x06
#define ASN1_OCTET_STRING   0x04
#define ASN1_MECH_TYPE      0xa0
#define ASN1_MECH_TOKEN     0xa2
#define ASN1_SUPPORTED_MECH 0xa1
#define ASN1_RESPONSE_TOKEN 0xa2
#define ASN1_MECH_LIST_MIC  0xa3
#define ASN1_ENUMERATED     0x0a

extern const uint8_t spnego_oid[];
extern const uint8_t ms_krb5_oid[];
extern const uint8_t krb5_oid[];
extern const uint8_t krb5_utu_oid[];
extern const uint8_t ntlmssp_oid[];

/*
NegotiationToken ::= CHOICE {
    negTokenInit    [0] NegTokenInit,    -> 0xa0
    negTokenResp    [1] NegTokenResp     -> 0xa1
}
*/
typedef enum {
    NEG_TOKEN_INIT,
    NEG_TOKEN_RESP,
    NEG_TOKEN_UNKNOWN
} neg_token_t;

/*
NegHints ::= SEQUENCE {
         hintName[0] GeneralString OPTIONAL,                  -> 0xa0
         hintAddress[1] OCTET STRING OPTIONAL                 -> 0xa1  
 }
NegTokenInit2 ::= SEQUENCE {
         mechTypes[0] MechTypeList OPTIONAL,                  -> 0xa0
         reqFlags [1] ContextFlags OPTIONAL,                  -> 0xa1
         mechToken [2] OCTET STRING OPTIONAL,                 -> 0xa2
         negHints [3] NegHints OPTIONAL,                      -> 0xa3
         mechListMIC [4] OCTET STRING OPTIONAL,               -> 0xa4
         ...
 }
*/
typedef struct spnego_neg_token_init_t {
    // mechTypes: 0xa0
    asn1_node_t *mech_types;

    // reqFlags: 0xa1
    uint8_t req_flags;

    // mechToken: 0xa2
    uint8_t *mech_token;
    size_t mech_token_len;

    // negHints: 0xa3
    asn1_node_t *neg_hints;

    // mechListMIC: 0xa4
    uint8_t *mech_list_mic;
    size_t mech_list_mic_len;
    
} spnego_neg_token_init_t;


/*
NegTokenResp ::= SEQUENCE {
    negState       [0] ENUMERATED {                            -> 0xa0
        accept-completed    (0),
        accept-incomplete   (1),
        reject              (2),
        request-mic         (3)
    }                                 OPTIONAL,
        -- REQUIRED in the first reply from the target
    supportedMech   [1] MechType      OPTIONAL,                -> 0xa1
        -- present only in the first reply from the target
    responseToken   [2] OCTET STRING  OPTIONAL,                -> 0xa2
    mechListMIC     [3] OCTET STRING  OPTIONAL,                -> 0xa3
    ...
}
*/
typedef struct spnego_neg_token_resp_t {
    // negState: 0xa0
    uint8_t *neg_state;
    size_t neg_state_len;

    // supportedMech: 0xa1
    uint8_t *supported_mech;
    size_t supported_mech_len;

    // responseToken: 0xa2
    uint8_t *response_token;
    size_t response_token_len;

    // mechListMIC: 0xa3
    uint8_t *mech_list_mic;
    size_t mech_list_mic_len;

} spnego_neg_token_resp_t;

typedef struct spnego_neg_token_t {
    neg_token_t type;

    union {
        spnego_neg_token_init_t init_token;
        spnego_neg_token_resp_t resp_token;
    } token;
    
} spnego_neg_token_t;

spnego_dec_error_t spnego_decode(asn1_tree_t asn1_tree, spnego_neg_token_t **resp);
spnego_dec_error_t spnego_decode_init(asn1_tree_t asn1_tree, spnego_neg_token_t *resp);
spnego_dec_error_t spnego_decode_resp(asn1_tree_t asn1_tree, spnego_neg_token_t *resp);





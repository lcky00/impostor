#include "spnego_decoder.h"

const uint8_t spnego_oid[]      = {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02};
const uint8_t ms_krb5_oid[]     = {0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02};
const uint8_t krb5_oid[]        = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02};
const uint8_t krb5_utu_oid[]    = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03};
const uint8_t ntlmssp_oid[]     = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a};


int check_spnego_oid(uint8_t *oid, int dim) {
    if (!oid) return 0;

    size_t len = sizeof(spnego_oid);

    if (dim != len) return 0;

    for (int i = 0; i < len; i++) {
        if (oid[i] != spnego_oid[i]) return 0;
    }

    return 1;
}

spnego_dec_error_t spnego_decode(asn1_tree_t asn1_tree, spnego_neg_token_t **resp) {
    if (!asn1_tree) return SPNEGO_DEC_ERR_INVALID_ASN1_TREE;
    if (!resp) return SPNEGO_DEC_ERR_INVALID_ARG;
    
    // If the first node is the GSSAPI token then skip
    asn1_node_t *spnego_node = NULL;
    if (asn1_tree->tag == ASN1_AID) {
        for (int i = 0; i < asn1_tree->size; i++) {
            asn1_node_t *node = asn1_tree->child_nodes[i];
            if (!node) continue;

            switch (node->tag) {
                case ASN1_OID:
                    if (!check_spnego_oid(node->data, node->data_dim)) 
                        return SPNEGO_DEC_ERR_INVALID_OID;
                    break;

                // If we find a valid tag
                case SPNEGO_INIT_TAG:
                case SPNEGO_RESP_TAG:
                    spnego_node = asn1_tree->child_nodes[i];
                    break;
                
                default:
                    return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
            }
        }
    }

    if (spnego_node) asn1_tree = spnego_node;
    if (!asn1_tree) return SPNEGO_DEC_ERR_INVALID_ASN1_NODE;

    *resp = calloc(1, sizeof(spnego_neg_token_t));
    if (!resp) {
        *resp = NULL;
        return SPNEGO_DEC_ERR_ALLOC;
    }

    spnego_dec_error_t res;
    switch (asn1_tree->tag) {
        case SPNEGO_INIT_TAG:
            (*resp)->type = NEG_TOKEN_INIT;
            res = spnego_decode_init(asn1_tree, *resp);
            if (res < SPNEGO_OK) {
                free(*resp);
                *resp = NULL;
                return res;
            }
            break;
        case SPNEGO_RESP_TAG:
            (*resp)->type = NEG_TOKEN_RESP;
            res = spnego_decode_resp(asn1_tree, *resp);
            if (res < SPNEGO_OK) {
                free(*resp);
                *resp = NULL;
                return res;
            }
            break;
        default:
            free(*resp);
            *resp = NULL;
            return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
    }

    return SPNEGO_OK;
}

spnego_dec_error_t spnego_decode_init(asn1_tree_t asn1_tree, 
    spnego_neg_token_t *resp) {
    
    if (!asn1_tree || asn1_tree->size <= 0) return SPNEGO_DEC_ERR_INVALID_ASN1_NODE;
    if (!resp) return SPNEGO_DEC_ERR_INVALID_ARG;

    asn1_tree = asn1_tree->child_nodes[0];

    if (!asn1_tree) return SPNEGO_DEC_ERR_INVALID_ASN1_NODE;
    if (asn1_tree->tag != ASN1_SEQUENCE) return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
    
    for (int i = 0; i < asn1_tree->size; i++) {
        asn1_node_t *node = asn1_tree->child_nodes[i];
        if (!node) continue;

        switch (node->tag) {
            // 0xa0
            case SPNEGO_INIT_MECHTYPES:
                if (node->size > 0 && node->child_nodes[0] != NULL)
                    resp->token.init_token.mech_types = node->child_nodes[0];
                break;
            
            // 0xa2
            case SPNEGO_INIT_MECHTOKEN:
                if (node->size > 0 && node->child_nodes[0] != NULL) {
                    resp->token.init_token.mech_token = node->child_nodes[0]->data;
                    resp->token.init_token.mech_token_len = node->child_nodes[0]->data_dim;
                }
                break;
            // 0xa3
            case SPNEGO_INIT_NEGHINTS:
                if (node->size > 0 && node->child_nodes[0] != NULL)
                    resp->token.init_token.neg_hints = node->child_nodes[0];
                break;

            // 0xa4
            // 0xa1
            case SPNEGO_INIT_REFLAGS:
            case SPNEGO_INIT_MECHLISTMIC:
                // TODO
                break;
            
            default:
                return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
        }

    }

    return SPNEGO_OK;
}

spnego_dec_error_t spnego_decode_resp(asn1_tree_t asn1_tree, 
    spnego_neg_token_t *resp) {
    
    if (!asn1_tree || asn1_tree->size <= 0) return SPNEGO_DEC_ERR_INVALID_ASN1_NODE;
    if (!resp) return SPNEGO_DEC_ERR_INVALID_ARG;

    asn1_tree = asn1_tree->child_nodes[0];
    
    if (!asn1_tree) return SPNEGO_DEC_ERR_INVALID_ASN1_NODE;
    if (asn1_tree->tag != ASN1_SEQUENCE) return SPNEGO_DEC_ERR_UNEXPECTED_TAG;

    for (int i = 0; i < asn1_tree->size; i++) {
        asn1_node_t *node = asn1_tree->child_nodes[i];

        if (!node) continue;

        switch (node->tag) {
            // 0xa0
            case SPNEGO_RESP_NEGSTATE:
                if (node->size > 0 && node->child_nodes[0] != NULL) {
                    resp->token.resp_token.neg_state = node->child_nodes[0]->data;
                    resp->token.resp_token.neg_state_len = node->child_nodes[0]->data_dim;
                }
                break;
            // 0xa1
            case SPNEGO_RESP_SUPORTED_MECH:
                if (node->size > 0 && node->child_nodes[0] != NULL) {
                    resp->token.resp_token.supported_mech = node->child_nodes[0]->data;
                    resp->token.resp_token.supported_mech_len = node->child_nodes[0]->data_dim;
                }
                break;
            // 0xa2
            case SPNEGO_RESP_RESPONSE_TOKEN:
                if (node->size > 0 && node->child_nodes[0] != NULL) {
                    resp->token.resp_token.response_token = node->child_nodes[0]->data;
                    resp->token.resp_token.response_token_len = node->child_nodes[0]->data_dim;
                }
                break;
            // 0xa3
            case SPNEGO_RESP_MECH_LIST_MIC:
                if (node->size > 0 && node->child_nodes[0] != NULL) {
                    resp->token.resp_token.mech_list_mic = node->child_nodes[0]->data;
                    resp->token.resp_token.mech_list_mic_len = node->child_nodes[0]->data_dim;
                }
                break;
            
            default:
                return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
        }
    }

    return SPNEGO_OK;
}


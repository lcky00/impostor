#include "spnego_decoder.h"
#include <stdio.h>

int check_spnego_oid(uint8_t *oid, int dim) {
    if (!oid) return 0;

    size_t len = sizeof(spnego_oid);

    if (dim != len) return 0;

    for (int i = 0; i < len; i++) {
        if (oid[i] != spnego_oid[i]) return 0;
    }

    return 1;
}

spnego_dec_error_t snpego_decode(asn1_tree_t asn1_tree, spnego_neg_token_t **resp) {
    if (asn1_tree == NULL) return SPNEGO_DEC_ERR_INVALID_ASN1_TREE;
    
    // If the first node is the GSSAPI token then skip
    if (asn1_tree->tag == ASN1_AID) {
        for (int i = 0; i < asn1_tree->size; i++) {
            asn1_node_t *node = asn1_tree->child_nodes[i];

            switch (node->tag) {
                case 0x6:
                    if (!check_spnego_oid(node->data, node->data_dim)) 
                        return SPNEGO_DEC_ERR_INVALID_DATA;
                    break;

                // If we find a valid tag
                case SPNEGO_INIT_TAG:
                case SPNEGO_RESP_TAG:
                    asn1_tree = asn1_tree->child_nodes[i];
                    break;
                
                default:
                    return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
            }
        }
    }

    *resp = calloc(1, sizeof(spnego_neg_token_t));
    if (!resp) {
        *resp = NULL;
        return SPNEGO_DEC_ERR_ALLOC;
    }

    switch (asn1_tree->tag) {
        case SPNEGO_INIT_TAG:
            (*resp)->type = NEG_TOKEN_INIT;
            spnego_decode_init(asn1_tree, *resp);
            break;
        case SPNEGO_RESP_TAG:
            (*resp)->type = NEG_TOKEN_RESP;
            spnego_decode_resp(asn1_tree, *resp);
            break;
        default:
            return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
    }

    return SPNEGO_OK;
}

spnego_dec_error_t spnego_decode_init(asn1_tree_t asn1_tree, 
    spnego_neg_token_t *resp) {
    
    if (asn1_tree->size <= 0) return 0;

    asn1_tree = asn1_tree->child_nodes[0];
    if (asn1_tree->tag != ASN1_SEQUENCE) return 0;
    
    for (int i = 0; i < asn1_tree->size; i++) {
        asn1_node_t *node = asn1_tree->child_nodes[i];
        switch (node->tag) {
            // 0xa0
            case SPNEGO_INIT_MECHTYPES:
                resp->token.init_token.mech_types = node->child_nodes[0];
                break;
            // 0xa1
            case SPNEGO_INIT_REFLAGS:

                break;
            // 0xa2
            case SPNEGO_INIT_MECHTOKEN:
                resp->token.init_token.mech_token = node->child_nodes[0]->data;
                resp->token.init_token.mech_token_len = node->child_nodes[0]->data_dim;
                break;
            // 0xa3
            case SPNEGO_INIT_NEGHINTS:
                
                break;
            // 0xa4
            case SPNEGO_INIT_MECHLISTMIC:

                break;
            
            default:
                return SPNEGO_DEC_ERR_UNEXPECTED_TAG;
        }

    }

    printf("%d\n", resp->type);
}

spnego_dec_error_t spnego_decode_resp(asn1_tree_t asn1_tree, 
    spnego_neg_token_t *resp) {
    
    printf("%d\n", resp->type);
}


int main() {
    unsigned char buffer2[] = {
        0x60, 0x48, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e,
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a, 0xa2, 0x2a,
        0x04, 0x28, 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x15, 0x82,
        0x08, 0x62, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f
    };
    // Calculate buffer length dynamically instead of hardcoding
    size_t buffer_len = sizeof(buffer2);

    

    asn1_tree_t tree;
    asn1_parser_error_t res = parse(buffer2, buffer_len, &tree);

    if (res < PARSER_OK) {
        printf("Error: 0x%x\n", res);
        return 1;
    }

    spnego_neg_token_t *resp;
    snpego_decode(tree, &resp);

    printf("%d\n", resp->type);
    printf("%d\n", resp->token.init_token.req_flags);

    asn1_tree_free(&tree);
}
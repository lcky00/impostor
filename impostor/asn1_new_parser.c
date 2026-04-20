#include "asn1_new_parser.h"

#include <string.h>

#define ASN1_NODE_INIT_ALLOC_CHILD 10
#define ASN1_STACK_INIT_ALLOC 10
#define PARSER_STACK_MAX_SIZE 16

/**************************************************/
//                Parser Utils
/**************************************************/

asn1_parser_error_t ctx_buffer_new(uint8_t *data, size_t dim, ctx_buffer_t *out) {
    if (!out || !data) return ERROR_INVALID_ARGS;
    
    out->dim = dim;
    out->data = data;

    return PARSER_OK;
}


uint8_t ctx_buffer_is_safe_offset(ctx_buffer_t buffer, size_t offset) {
    return buffer.dim > 0 && offset <= buffer.dim - 1;
}

uint8_t ctx_buffer_is_safe_len(ctx_buffer_t buffer, size_t offset, size_t len) {
    return ctx_buffer_is_safe_offset(buffer, offset)
            && buffer.dim - offset >= len; // NO "-1" because we also count che offset itself
}

asn1_parser_error_t ctx_buffer_read(ctx_buffer_t buffer, size_t start_offset, size_t bytes_to_read, uint8_t **out) {
    // Check for read safety
    if (!out) return ERROR_INVALID_ARGS;
    
    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;

    if (!ctx_buffer_is_safe_len(buffer, start_offset, bytes_to_read)) 
        return ERROR_UNSAFE_LEN;

    *out = calloc(bytes_to_read, sizeof(uint8_t));
    if (!*out) return ERROR_ALLOCATION;

    memcpy(*out, buffer.data + start_offset, bytes_to_read);

    return PARSER_OK;
}


asn1_parser_error_t tlv_extract_len(ctx_buffer_t buffer, size_t offset, uint8_t *num_bytes, uint64_t *len) {
    if (!num_bytes || !len) return ERROR_INVALID_ARGS;

    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;

    // Safe read the len byte
    uint8_t l_byte;
    if (!ctx_buffer_is_safe_len(buffer, offset, sizeof(l_byte))) 
        return ERROR_UNSAFE_LEN;
    l_byte = buffer.data[offset];

    // Check the Len form
    uint8_t form = (l_byte & 0x80);

    // Long-form
    if (form != 0) {
        *num_bytes = (l_byte & 0x7F);

        if (*num_bytes > PARSER_MAX_NUM_BYTES_FOR_LEN) 
            return ERROR_PARSER_MAX_NUM_BYTES_FOR_LEN;

        // Read the effective len
        offset++;
        if (!ctx_buffer_is_safe_len(buffer, offset, *num_bytes)) 
            return ERROR_UNSAFE_LEN;
        
        *len = 0;

        uint8_t cpy_num_bytes = *num_bytes;
        while (cpy_num_bytes > 0) {
            uint64_t b = buffer.data[offset++];
            *len = (*len << 8) | b;
            cpy_num_bytes--;
        }
        *num_bytes += 1; // Add Tag Byte

    }
    // Short-form
    else {
        *num_bytes = 1;
        *len = (l_byte & 0x7F);
    }

    if (!ctx_buffer_is_safe_len(buffer, offset, *len)) 
        return ERROR_UNSAFE_LEN;

    return PARSER_OK;
}


asn1_parser_error_t tlv_read_from_buffer(ctx_buffer_t buffer, size_t start_offset, tlv_t *tlv_out) {
    if (!buffer.data) return ERROR_INVALID_BUFFER_DATA;
    
    if (!tlv_out) return ERROR_INVALID_ARGS;

    size_t offset = start_offset;

    // Check safety of offset
    if (!ctx_buffer_is_safe_offset(buffer, offset)) 
        return ERROR_UNSAFE_BUFFER_OFFSET;

    // Safe read tag
    asn1_tag_t tag;
    if (!ctx_buffer_is_safe_len(buffer, offset, sizeof(tag))) 
        return ERROR_UNSAFE_LEN;
    
    tag = buffer.data[offset++];

    // Safe extract len info
    size_t tag_value_len, tag_value_len_bytes;
    asn1_parser_error_t res;
    if ((res = tlv_extract_len(buffer, offset, &tag_value_len_bytes, &tag_value_len)) < PARSER_OK) 
        return res;

    offset += tag_value_len_bytes;

    // Prepare the tlv obj to return
    tlv_out->offset_start = start_offset;
    tlv_out->tag = tag;
    tlv_out->tag_value_len = tag_value_len;
    tlv_out->tag_value_len_bytes = tag_value_len_bytes;
    tlv_out->offset_data = offset;

    return PARSER_OK;
}

static asn1_parser_error_t asn1_node_realloc_childs(asn1_node_t *out) {
    if (!out) return ERROR_INVALID_ARGS;

    // Checks if there is somethigs to reallocate
    if (!out->child_nodes) return ERROR_NOTHING_TO_REALLOC;

    asn1_node_t **new_ptr = realloc(out->child_nodes, sizeof(asn1_node_t *) * (out->dim * 2));
    if (!new_ptr) return ERROR_REALLOC;

    out->child_nodes = new_ptr;

    memset(out-> child_nodes + out->dim, 0, out->dim * sizeof(asn1_node_t *));

    out->dim *= 2;

    return PARSER_OK;
}

static asn1_parser_error_t asn1_node_alloc_childs(asn1_node_t *out) {
    if (!out) return ERROR_INVALID_ARGS;

    // check if is already allocated
    if (out->child_nodes) return ERROR_DATA_ALREADY_ALLOC;

    out->child_nodes = calloc(ASN1_NODE_INIT_ALLOC_CHILD, sizeof(asn1_node_t *));
    if (!out->child_nodes) return ERROR_ALLOCATION;

    out->dim = ASN1_NODE_INIT_ALLOC_CHILD;
    out->size = 0;

    return PARSER_OK;
}

asn1_parser_error_t asn1_node_new(asn1_node_t **out) {
    if (!out) return ERROR_INVALID_ARGS;

    // Check if is already allocated
    if (*out) return ERROR_DATA_ALREADY_ALLOC;

    *out = calloc(1, sizeof(asn1_node_t));
    if (!*out) return ERROR_ALLOCATION;

    return PARSER_OK;
}

static void asn1_node_free(asn1_node_t **node) {
    if (!node || !*node) return;

    // If is a primitive node
    if ((*node)->data) { 
        free((*node)->data);
        (*node)->data = NULL;
    }

    // If is a constructed node
    if ((*node)->child_nodes) {
        free((*node)->child_nodes);
        (*node)->child_nodes = NULL;
    }

    free(*node);
    *node = NULL;
}

static void asn1_tree_free_recv(asn1_node_t *node) {
    if (!node) return;

    for (size_t i = 0; i < node->size; i++) {
        asn1_tree_free_recv(node->child_nodes[i]);
    }

    asn1_node_free(&node);
}

asn1_parser_error_t asn1_tree_free(asn1_node_t **tree) {
    if (!tree || !*tree) return -1;

    asn1_parser_error_t res;

    // Initialize auxiliary stack for free the tree
    size_t stack_top = 0;
    size_t stack_dim = 100;
    asn1_node_t **stack_free = calloc(stack_dim, sizeof(asn1_node_t *));
    if (!stack_free) return -1;
    
    // Push the first node in the stack
    stack_free[0] = *tree;
    stack_top++;

    while (stack_top > 0) {
        // Top from the stack
        asn1_node_t *aux = stack_free[--stack_top];
        // Push each childs in the satck for free
        for (size_t i = 0; i < aux->size; i++) {

            // Check if there is space
            if (stack_top == stack_dim) {
                asn1_node_t **tmp = realloc(stack_free, sizeof(asn1_node_t *) * stack_dim * 2);
                
                // If realloc fails, heap is full, try with recursion for stack memory
                if (!tmp) {
                    stack_top -= i;
                    while(stack_top > 0) {
                        asn1_node_t *node = stack_free[--stack_top];
                        asn1_tree_free_recv(node);
                    }
                    free(stack_free);

                    // Free aux that is outside from stack
                    asn1_tree_free_recv(aux);

                    *tree = NULL;

                    return PARSER_OK;
                }

                stack_dim *= 2;
                stack_free = tmp;
            }

            stack_free[stack_top++] = aux->child_nodes[i];
        }
        // Free the node
        asn1_node_free(&aux);
    }
    
    free(stack_free);
    *tree = NULL;
    return PARSER_OK;
}

/**************************************************/
//                Stack Utils
/**************************************************/

asn1_parser_error_t parser_stack_new(parser_stack_t **out) {
    if (!out) return -1;

    // Check if is already allocated
    if (*out) return -1;

    *out = calloc(1, sizeof(parser_stack_t));
    if (!*out) return -1;

    // Allocate initial entries
    (*out)->stack_entries = calloc(ASN1_STACK_INIT_ALLOC, sizeof(parser_entry_stack_t *));
    if (!(*out)->stack_entries) {
        free(*out);
        *out = NULL;
        return -1;
    }

    (*out)->dim = ASN1_STACK_INIT_ALLOC;

    return PARSER_OK;
}

/**
 * precondition: tlv is already safe. No tlv safety check is performed 
 */
asn1_parser_error_t parser_entry_stack_new(asn1_node_t *node, tlv_t tlv, parser_entry_stack_t **out) {
    if (!out || !node) return -1;

    // Check is is already allocated
    if (*out) return -1;

    *out = calloc(1, sizeof(parser_entry_stack_t));
    if (!*out) return -1;

    (*out)->node = node;
    (*out)->tlv = tlv;

    return PARSER_OK;
}


asn1_parser_error_t parser_stack_empty(parser_stack_t *stack, uint8_t *out) {
    if (!stack || !out) return -1; // Aggiunto controllo su out

    *out = (stack->size == 0);
    return PARSER_OK;
}

/**
 * Free stack entry NOT the ASN1 node inside.
 */
asn1_parser_error_t parser_stack_free_entry(parser_entry_stack_t **entry) {
    if (!entry || !*entry) return -1;

    free(*entry);
    *entry = NULL;

    return PARSER_OK;
}

asn1_parser_error_t parser_stack_free(parser_stack_t **stack) {
    if (!stack || !*stack) return -1;

    size_t dim, size;
    dim = (*stack)->dim;
    size = (*stack)->size;
    parser_entry_stack_t **s = (*stack)->stack_entries;

    // Free stack entries
    for (size_t i = 0; i < dim; i++) {
        if (s[i]) {
            parser_stack_free_entry(&s[i]);
        }
    }

    free(*stack);
    *stack = NULL;

    return PARSER_OK;
}

static asn1_parser_error_t parser_stack_expand(parser_stack_t *stack) {
    if (!stack) return -1;

    if (!stack->stack_entries) return -1;

    size_t new_dim = stack->dim * 2;
    parser_entry_stack_t **new_ptr = realloc(stack->stack_entries, sizeof(parser_entry_stack_t*) * new_dim);
    if (!new_ptr) return -1;

    stack->stack_entries = new_ptr;
    stack->dim = new_dim;

    return PARSER_OK;

}

asn1_parser_error_t parser_stack_push(parser_stack_t *stack, parser_entry_stack_t *entry){
    if (!stack || !entry) return -1;

    // Check if list entries is allocated
    if (!stack->stack_entries) return -1;

    // Check if we reach the max nesting level
    if (stack->size >= PARSER_STACK_MAX_SIZE) return -1;

    // Check available space
    asn1_parser_error_t res;
    if (stack->size >= stack->dim) {
        // Reallocate stack with more space
        if ((res = parser_stack_expand(stack)) < PARSER_OK) 
            return res;
    }

    // Push the entry
    stack->stack_entries[stack->size++] = entry;

    return PARSER_OK;
}

asn1_parser_error_t parser_stack_pop(parser_stack_t *stack) {
    if (!stack) return -1;

    // Check if list entries is allocated
    if (!stack->stack_entries) return -1;

    asn1_parser_error_t res;

    // Check if is empty
    uint8_t empty = 0;
    if ((res = parser_stack_empty(stack, &empty)) < PARSER_OK)
        return res;

    if (empty) return -1;

    // Free the entry
    if ((res = parser_stack_free_entry(&stack->stack_entries[stack->size - 1])) < PARSER_OK)
        return res;

    stack->size--;

    return PARSER_OK;    
}

asn1_parser_error_t parser_stack_top(parser_stack_t *stack, parser_entry_stack_t **out) {
    if (!stack || !out) return -1;

    // Check if list entries is allocated
    if (!stack->stack_entries) return -1;

    asn1_parser_error_t res;

    // Check if is empty
    uint8_t empty = 0;
    if ((res = parser_stack_empty(stack, &empty)) < PARSER_OK)
        return res;

    if (empty) return -1;

    *out = stack->stack_entries[stack->size - 1];

    return PARSER_OK;
}

/**************************************************/
//                Main Parser
/**************************************************/

static asn1_parser_error_t parse_constructed_node() {}
static asn1_parser_error_t parse_primitive_node() {}

asn1_parser_error_t parse(uint8_t *buffer, size_t len, asn1_node_t **out) {
    // Costruzione primo nodo:
    // - estrazione TLV
    // - push stack
    
    // Finchè stack pieno:
    // - Top dallo stack:
    //   - Se primitive:
    //     - riempio il nodo con il value
    //     - Pop stack
    //     - Top dallo stack e inserisco nella lista del nodo da cui ho fatto top
    //       Se top è vuoto allora c'è solo qusto nodo, niente push sul parent
    //     - Pop dallo stack
    //
    //   - Se constructed:
    //     - controllo della ret_len per vedere se ha raggiunto il massimo della dim 
    //       da size tlv
    //     - check per vedere se ha allocato child list: nel caso allocare, vuol dire che è stato 
    //       preso dallo stack per le prima volta.
    //     - se ret_len == tlv_len: 
    //       - push del nodo sul nodo del top dello stack
    //       - aggiornamento ret_len del parent
    //       - pop stack
    //     - se ret_len < tlv_len:
    //       - extract tlv da Value in tlv
    //       - creazione entry stack, creazione nodo asn1; metto nodo e tlv in stack entry.
    //       - push sullo stack 
    //
    //     - else (ret_len > tlv_len): errore

    if (!buffer) return -1;
    if (!out) return -1;

    asn1_parser_error_t res;

    // Build ctx_buffer
    ctx_buffer_t ctx_buffer;
    if ((res = ctx_buffer_new(buffer, len, &ctx_buffer)) < PARSER_OK)
        return res;

    // Build stack
    parser_stack_t *stack;
    if ((res = parser_stack_new(&stack)) < PARSER_OK)
        return res;

    // Extract first tlv
    tlv_t tlv;
    if((res = tlv_read_from_buffer(ctx_buffer, 0, &tlv)) < PARSER_OK) {
        parser_stack_free(&stack);
        return res;
    }
    // Build ASN1 node
    asn1_node_t *root;
    if ((res = asn1_node_new(&root)) < PARSER_OK) {
        parser_stack_free(&stack);
        return res;
    }
    root->tag = tlv.tag;

    // Create first stack entry
    parser_entry_stack_t *entry;
    if((res = parser_entry_stack_new(root, tlv, &entry)) < PARSER_OK) {
        parser_stack_free(&stack);
        
        return res;
    }



}

/*********************************************/

int main() {

}


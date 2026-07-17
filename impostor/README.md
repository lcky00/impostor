# SPNEGO Decoder Library

A lightweight, *zero-copy* C library for decoding **SPNEGO** (Simple and Protected GSS-API Negotiation Mechanism, RFC 4178) tokens. 

This library acts as an intermediate layer in a network parsing stack: it receives an ASN.1 syntax tree generated from a raw payload, identifies and decodes the SPNEGO constructs, and exposes the inner tokens (Kerberos, NTLM) ready to be passed to their respective parsers.

## Table of Contents
- [Architecture and Design](#architecture-and-design)
- [ASN.1 Structures and C Mapping](#asn1-structures-and-c-mapping)
- [API Reference](#api-reference)
- [Decoding Workflow (Full Example)](#decoding-workflow-full-example)
- [Memory Management](#memory-management)

---

## Architecture and Design

The library is designed with a **zero-copy** approach. During decoding, binary data (such as encapsulated NTLM or Kerberos tokens) are not re-allocated or copied in memory. The SPNEGO C structures simply hold pointers to the nodes of the underlying `asn1_tree_t` tree.

The layer automatically recognizes whether the SPNEGO token is encapsulated in a generic GSS-API header (Tag `0x60`, Application Constructed) by verifying the SPNEGO Object Identifier (OID) (`1.3.6.1.5.5.2`), or if it is a direct token.

---

## ASN.1 Structures and C Mapping

SPNEGO specifies two main types of tokens, encapsulated within a `CHOICE` structure. The library directly maps these RFC specifications into C structures.

### 1. The Negotiation Token (CHOICE)
In ASN.1, the root token is defined as:
```asn1
NegotiationToken ::= CHOICE {
    negTokenInit  [0] NegTokenInit,  -- Tag 0xa0
    negTokenResp  [1] NegTokenResp   -- Tag 0xa1
}
```
In the library, this is represented by the `spnego_neg_token_t` struct, which exposes an `enum` to identify the token type and a `union` containing the specific structure:
```c
typedef struct spnego_neg_token_t {
    neg_token_t type; // NEG_TOKEN_INIT, NEG_TOKEN_RESP or NEG_TOKEN_UNKNOWN
    union {
        spnego_neg_token_init_t init_token;
        spnego_neg_token_resp_t resp_token;
    } token;
} spnego_neg_token_t;
```

### 2. NegTokenInit (Initialization)
Sent by the client to propose the supported authentication mechanisms and, optionally, an initial token (Optimistic Token).

| ASN.1 Field | Context Tag | Corresponding C Type | Description |
|---|---|---|---|
| `mechTypes` | `[0] 0xa0` | `asn1_node_t *` | List of OIDs for supported mechanisms (e.g., Kerberos, NTLMSSP). |
| `reqFlags` | `[1] 0xa1` | `uint8_t` | Context flags (mutual authentication, integrity, etc.). |
| `mechToken` | `[2] 0xa2` | `uint8_t *` + `size_t` | The payload of the first preferred mechanism (Zero-copy pointer). |
| `negHints` | `[3] 0xa3` | `asn1_node_t *` | Optional hints for the negotiation. |
| `mechListMIC`| `[4] 0xa4` | `uint8_t *` + `size_t` | Optional Message Integrity Code (signature). |

### 3. NegTokenResp (Response)
Sent by the server to confirm the selected mechanism, the negotiation state, and to exchange further challenge/response tokens.

| ASN.1 Field | Context Tag | Corresponding C Type | Description |
|---|---|---|---|
| `negState` | `[0] 0xa0` | `uint8_t *` + `size_t` | State: `accept-completed(0)`, `accept-incomplete(1)`, `reject(2)`. |
| `supportedMech` | `[1] 0xa1` | `uint8_t *` + `size_t` | The OID of the mechanism actually accepted by the server. |
| `responseToken` | `[2] 0xa2` | `uint8_t *` + `size_t` | The response payload (e.g., the NTLM Challenge or Authenticate). |
| `mechListMIC` | `[3] 0xa3` | `uint8_t *` + `size_t` | Optional Message Integrity Code. |

---

## API Reference

The decoding engine is based on three main functions. The user typically interacts only with `spnego_decode` (note: ensure you use the correct spelling in your header).

*   **`spnego_dec_error_t spnego_decode(asn1_tree_t asn1_tree, spnego_neg_token_t **resp)`**
    *   **Role:** Main entry point. Checks the GSS-API header, verifies the SPNEGO OID (`1.3.6.1.5.5.2`) using `check_spnego_oid()`, allocates the `spnego_neg_token_t` structure, and calls the specific decoder (Init or Resp) based on the ASN.1 tag (`0xa0` or `0xa1`).
*   **`spnego_decode_init(...)` / `spnego_decode_resp(...)`**
    *   **Role:** Internal functions (or manually callable if the token is unwrapped). They iterate over the child nodes of the ASN.1 sequence, match the Context Tags (`0xa0`, `0xa1`, etc.), and populate the structure's pointers while ignoring unexpected tags.

---

## Decoding Workflow (Full Example)

The following example demonstrates a complete application parsing chain. It reads a raw payload, creates the ASN.1 tree, decodes the SPNEGO wrapper, and extracts an NTLMSSP payload to pass it to the final parser.

```c
#include "spnego_decoder.h"
#include "ntlm_parser.h"
#include <stdio.h>
#include <stdlib.h>

// Callback for ASN.1 logging
void asn1_logger(size_t ident, const char *format, va_list args) {
    for (size_t i = 0; i < ident; i++) {
        printf("  |");
    }
    vprintf(format, args);
}

// Callback for NTLM logging
void ntlm_logger(const char *format, va_list args) {
    vprintf(format, args);
}

int main() {
    // Raw network buffer: contains a GSS-API wrapper, a SPNEGO NegTokenResp
    // and inside it an NTLMSSP token.
    unsigned char buffer[] = {
        0xa1, 0x82, 0x01, 0xfc, 0x30, 0x82, 0x01, 0xf8, 0xa2, 0x82, 0x01, 0xf4, 0x04, 0x82, 0x01, 0xf0,
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
        0xd9, 0x34, 0x25, 0xe6, 0x04, 0x32, 0xc4, 0x60, 0xf2, 0x7e, 0x1c, 0xa5, 0x35, 0xbe, 0xf6, 0x22
    };
    size_t buffer_len = sizeof(buffer);

    set_logger(asn1_logger);
    set_ntlm_logger(ntlm_logger);

    printf("[+] Parsing the ASN.1 ...\n");
    asn1_tree_t tree;
    asn1_parser_error_t asn_res = parse(buffer, buffer_len, &tree);
    if (asn_res < PARSER_OK) {
        printf("[-] ASN.1 Error: 0x%x\n", asn_res);
        return 1;
    }
    dump_asn1_tree(tree);

    printf("\n[+] SPNEGO logical decoding ...\n");
    spnego_neg_token_t *spnego_token;
    spnego_dec_error_t spnego_res = spnego_decode(tree, &spnego_token);
    
    if (spnego_res < SPNEGO_OK) {
        printf("[-] SPNEGO decoding error: 0x%x\n", spnego_res);
        asn1_tree_free(&tree);
        return 1;
    }

    // Ensure it is a NegTokenResp before proceeding
    if (spnego_token->type == NEG_TOKEN_RESP) {
        printf("\n[+] Extraction and Parsing of the internal protocol (NTLM)\n");
        
        ntlm_msg_t ntlm_msg;
        ntlm_buffer_ctx_t ntlm_ctx;
        
        // Zero-Copy handoff: we directly pass the pointer extracted by SPNEGO
        ntlm_parser_error ntlm_res = ntlm_ctx_buffer_init(
            spnego_token->token.resp_token.response_token,
            spnego_token->token.resp_token.response_token_len, 
            &ntlm_ctx
        );
        
        if (ntlm_res == NTLM_PARSER_OK) {
            parse_ntlm_msg(&ntlm_ctx, &ntlm_msg);
            dump_msg(&ntlm_msg); // Print NTLM details to screen
            free_ntlm_msg(&ntlm_msg); // NTLM Cleanup
        } else {
            printf("[-] NTLM buffer initialization error: 0x%x\n", ntlm_res);
        }
    }

    printf("\n[+] Phase 4: Memory Cleanup\n");
    // Free the SPNEGO structure
    free(spnego_token);
    // Free the ASN.1 tree (MUST be done at the very end to avoid Use-After-Free)
    asn1_tree_free(&tree);

    printf("[+] Finish.\n");
    return 0;
}
```

## Memory Management

Due to the zero-copy approach, the order in which memory is freed is critical to prevent *Use-After-Free* (UAF) or *Segmentation Faults*:

1.  **Application Data**: If secondary parsers (e.g., NTLM) have allocated memory based on the buffers extracted from SPNEGO, these must be freed first (e.g., `free_ntlm_msg`).
2.  **`spnego_neg_token_t`**: Must be freed using a simple `free()` call. The internal pointers (like `mech_token`, `response_token`) should not be freed individually, as they point to memory segments owned by the ASN.1 tree.
3.  **`asn1_tree_t`**: The original ASN.1 tree (and the raw network buffer associated with it, if dynamically allocated) must be deallocated **only at the end**. Destroying the tree earlier will invalidate the pointers extracted and passed to NTLM.
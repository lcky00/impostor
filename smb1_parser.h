#ifndef SMB1_PARSER_H
#define SMB1_PARSER_H

#include <stdint.h>
#include <stdlib.h>

/*************************************************/
/*                    FLAG                       */
/*************************************************/
#define SMB_FLAGS_LOCK_AND_READ_OK      0x01
#define SMB_FLAGS_BUF_AVAIL             0x02
#define SMB_FLAGS_CASE_INSENSITIVE      0x08
#define SMB_FLAGS_CANONICALIZED_PATHS   0x10
#define SMB_FLAGS_OPLOCK                0x20
#define SMB_FLAGS_OPBATCH               0x40
#define SMB_FLAGS_REPLY                 0x80

/*************************************************/
/*                    FLAG2                      */
/*************************************************/
#define SMB_FLAGS2_LONG_NAMES               0x0001
#define SMB_FLAGS2_EAS                      0x0002
#define SMB_FLAGS2_SMB_SECURITY_SIGNATURE   0x0004
#define SMB_FLAGS2_IS_LONG_NAME             0x0040
#define SMB_FLAGS2_DFS                      0x1000
#define SMB_FLAGS2_PAGING_IO                0x2000
#define SMB_FLAGS2_NT_STATUS                0x4000
#define SMB_FLAGS2_UNICODE                  0x8000
#define SMB_FLAGS2_COMPRESSED               0x0008
#define SMB_FLAGS2_SMB_SECURITY_SIGNATURE_REQUIRED 0x0010
#define SMB_FLAGS2_REPARSE_PATH             0x0400
#define SMB_FLAGS2_EXTENDED_SECURITY        0x0800


/*************************************************/
/*                 CAPABILITIES                  */
/*************************************************/
#define CAP_RAW_MODE                0x00000001
#define CAP_MPX_MODE                0x00000002
#define CAP_UNICODE                 0x00000004
#define CAP_LARGE_FILES             0x00000008
#define CAP_NT_SMBS                 0x00000010
#define CAP_RPC_REMOTE_APIS         0x00000020
#define CAP_STATUS32                0x00000040
#define CAP_LEVEL_II_OPLOCKS        0x00000080
#define CAP_LOCK_AND_READ           0x00000100
#define CAP_NT_FIND                 0x00000200
#define CAP_DFS                     0x00001000
#define CAP_INFOLEVEL_PASSTHRU      0x00002000
#define CAP_LARGE_READX             0x00004000
#define CAP_LARGE_WRITEX            0x00008000
#define CAP_LWIO                    0x00010000
#define CAP_UNIX                    0x00800000
#define CAP_COMPRESSED_DATA         0x02000000
#define CAP_DYNAMIC_REAUTH          0x20000000
#define CAP_PERSISTENT_HANDLES      0x40000000
#define CAP_EXTENDED_SECURITY       0x80000000

/*************************************************/
/*                 SECURITY MODE                 */
/*************************************************/
#define NEGOTIATE_USER_SECURITY                 0x01
#define NEGOTIATE_ENCRYPT_PASSWORDS             0x02
#define NEGOTIATE_SECURITY_SIGNATURES_ENABLED   0x04
#define NEGOTIATE_SECURITY_SIGNATURES_REQUIRED  0x08

/*************************************************/
/*                    ACTION                     */
/*************************************************/
#define SMB_SETUP_GUEST             0x0001
#define SMB_SETUP_USE_LANMAN_KEY    0x0002

/*************************************************/
/*                    COMMANDS                   */
/*************************************************/
#define SMB_COM_NEGOTIATE           0x72
#define SMB_COM_SESSION_SETUP_ANDX  0x73


/*************************************************/
/*                    ERRORS                     */
/*************************************************/
#define SMB_PARSER_OK 0x00000000

#define SMB_PARSER_ERR_EXTRACT 0x80000001
#define SMB_PARSER_ERR_SMB_SIGN 0x80000002
#define SMB_PARSER_ERR_INVALID_CMD 0x80000003
#define SMB_PARSER_ERR_ALLOC 0x80000004
#define SMB_PARSER_ERR_UNSAFE_LEN 0x80000005
#define SMB_PARSER_ERR_MISSING_SMB_DATA 0x80000006
#define SMB_PARSER_ERR_MISSING_SMB_PARAMS 0x80000007
#define SMB_PARSER_ERR_MALFORMED_SMB_MSG 0x80000008

#define SMB_PARSER_ERR_0x72_PARSING 0x80000009
#define SMB_PARSER_ERR_0x73_PARSING 0x8000000a
#define SMB_PARSER_ERR_NULL_ARG 0x8000000b

typedef int32_t smb_parser_error_t;

/* SMB HEADER */
typedef struct smb_header_t {
    uint8_t protocol[4];
    uint8_t command;
    uint8_t status[4];
    uint8_t flags;
    uint16_t flags2;
    uint16_t pid_high;
    uint8_t security_features[8];
    uint16_t reserved;
    uint16_t tid;
    uint16_t pid_low;
    uint16_t uid;
    uint16_t mid;
} smb_header_t;

/* SMB PARMETER */
typedef struct smb_parameters_t {
    uint8_t word_count;
    uint8_t *words;
} smb_parameters_t;

/* SMB DATA */
/**
 * Per string PADDING: il primo byte del tuo blocco Bytes cade sempre e 
 * in ogni caso in una posizione DISPARI rispetto 
 * all'inizio del pacchetto.
 */
typedef struct smb_data_t {
    uint16_t byte_count;
    uint8_t *bytes;
} smb_data_t;

/* SMB RAW MESSAGE*/
typedef struct smb_raw_msg_t {
    smb_header_t header;
    smb_parameters_t params;
    smb_data_t data;
} smb_raw_msg_t;


/*************************************************/
/*            SMB_COM_NEGOTIATE (0x72)           */
/*************************************************/

/* SMB_COM_NEGOTIATE (0x72) PARAMETERS */
typedef struct params_req_smb_com_negotiate_t {
    uint8_t null; // MUST be 0x00
} params_req_smb_com_negotiate_t;

typedef struct params_res_smb_com_negotiate_t {
    uint16_t dialect_index;
    uint8_t security_mode;
    uint16_t max_mpx_count;
    uint16_t max_number_vcs;
    uint32_t max_buffer_size;
    uint32_t max_raw_size;
    uint32_t session_key;
    uint32_t capabilities;
    uint64_t system_time;
    uint16_t server_time_zone;
    uint8_t challenge_length;
} params_res_smb_com_negotiate_t;


typedef struct {
    uint8_t buffer_format;
    uint8_t *dialect_string;
} smb_dialect;

/* SMB_COM_NEGOTIATE (0x72) DATA */
typedef struct data_req_smb_com_negotiate_t {
    uint16_t byte_count;
    size_t len;
    smb_dialect *dialects;
} data_req_smb_com_negotiate_t;

/**
 * In SMB_COM_NEGOTIATE (0x72) -> ByteCount (2 bytes): The number of bytes in the SMB_Data.Bytes array, which follows. 
 *  This field MUST be greater than or equal to 0x0010 (16 in decimal).
 */
typedef struct data_res_smb_com_negotiate_t {
    uint8_t server_guid[16];
    size_t len;
    uint8_t *security_blob;
} data_res_smb_com_negotiate_t;

/* SMB_COM_NEGOTIATE (0x72) REQUEST */
typedef struct smb_com_negotiate_req_t {
    params_req_smb_com_negotiate_t params;
    data_req_smb_com_negotiate_t data;
} smb_com_negotiate_req_t;

/* SMB_COM_NEGOTIATE (0x72) RESPONSE */
typedef struct smb_com_negotiate_res_t {
    params_res_smb_com_negotiate_t params;
    data_res_smb_com_negotiate_t data;    
} smb_com_negotiate_res_t;

/* SMB_COM_NEGOTIATE (0x72) MESSAGE */
typedef union {
    smb_com_negotiate_req_t req;
    smb_com_negotiate_res_t res;
} smb_com_negotiate_t;


/*************************************************/
/*       SMB_COM_SESSION_SETUP_ANDX (0x73)       */
/*************************************************/

/* SMB_COM_SESSION_SETUP_ANDX (0x73) PARAMS */
typedef struct params_req_smb_com_session_setup_andx_t {
    uint8_t and_x_command;
    uint8_t and_x_reserved;
    uint16_t and_x_offset;
    uint16_t max_buffer_size;
    uint16_t max_mpx_count;
    uint16_t vc_number;
    uint32_t session_key;
    uint16_t security_blob_len;
    uint32_t reserved;
    uint32_t capabilities;
} params_req_smb_com_session_setup_andx_t;

typedef struct params_res_smb_com_session_setup_andx_t {
    uint8_t and_x_command;
    uint8_t and_x_reserved;
    uint16_t and_x_offset;
    uint16_t action;
    uint16_t security_blob_len;
} params_res_smb_com_session_setup_andx_t;

/* SMB_COM_SESSION_SETUP_ANDX (0x73) DATA */
typedef struct data_smb_com_session_setup_andx_t {
    uint8_t *security_blob; // LEN -> security_blob_len in params
    // PADDING attenzione! Se l'offset rispetto all'header SMB è dispari, c'è 1 byte di padding
    /**
     * If SMB_FLAGS2_UNICODE is set in the Flags2 field of the SMB header of the request, 
     * then the name string MUST be a NULL-terminated array of 16-bit Unicode characters. 
     * Otherwise, the name string MUST be a NULL-terminated array of OEM characters. 
     * If the name string consists of Unicode characters, then this field MUST be aligned 
     * to start on a 2-byte boundary from the start of the SMB header
     */
    size_t native_os_len;
    uint8_t *native_os; 

    size_t native_lan_man_len;
    uint8_t *native_lan_man;
} data_smb_com_session_setup_andx_t;

/* SMB_COM_SESSION_SETUP_ANDX (0x73) REQUEST */
typedef struct smb_com_session_setup_andx_req_t {
    params_req_smb_com_session_setup_andx_t params;
    data_smb_com_session_setup_andx_t data;
} smb_com_session_setup_andx_req_t;

/* SMB_COM_SESSION_SETUP_ANDX (0x73) RESPONSE */
typedef struct smb_com_session_setup_andx_res_t {
    params_res_smb_com_session_setup_andx_t params;
    data_smb_com_session_setup_andx_t data;    
} smb_com_session_setup_andx_res_t;


/* SMB_COM_SESSION_SETUP_ANDX (0x73) MESSAGE */
typedef union {
    smb_com_session_setup_andx_req_t req;
    smb_com_session_setup_andx_res_t res;
} smb_com_session_setup_andx_t;

/*************************************************/
/*              SMB PARSED MESSAGE               */
/*************************************************/

typedef struct smb_parsed_msg_t {
    smb_header_t header;

    union {
        smb_com_negotiate_t negotiate;
        smb_com_session_setup_andx_t session_setup_andx;
    } command;
    
} smb_parsed_msg_t;

typedef struct ctx_msg_t {
    uint8_t *msg;
    size_t len;
    size_t offset;
    size_t base_offset;
} ctx_msg_t;


/*************************************************/
/*                  FUNCTIONS                    */
/*************************************************/

smb_parser_error_t smb_parse_msg(uint8_t *msg, size_t len, smb_raw_msg_t *parsed_msg);
smb_parser_error_t smb_parse_cmd(smb_raw_msg_t raw_msg, smb_parsed_msg_t *parsed_msg);

void free_smb_raw_msg(smb_raw_msg_t *msg);
void free_smb_cmd_msg(smb_parsed_msg_t *msg);


#endif // SMB1_PARSER_H
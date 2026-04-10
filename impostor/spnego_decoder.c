/**

0x60 = Application-specific SEQUENCE del GSS-API token iniziale
È il wrapper GSS-API, prima di arrivare a a0 / a1.

NegotiationToken ::= CHOICE {
    negTokenInit    [0] NegTokenInit,    -> 0xa0
    negTokenResp    [1] NegTokenResp     -> 0xa1
}

MechType ::= OBJECT IDENTIFIER
       -- OID represents each security mechanism as suggested by
       -- [RFC2743]

MechTypeList ::= SEQUENCE OF MechType

===================================
NegTokenInit ::= SEQUENCE {
    mechTypes       [0] MechTypeList,                            -> 0xa0
    reqFlags        [1] ContextFlags  OPTIONAL,                  -> 0xa1
        -- inherited from RFC 2478 for backward compatibility,   
        -- RECOMMENDED to be left out
    mechToken       [2] OCTET STRING  OPTIONAL,                  -> 0xa2
    mechListMIC     [3] OCTET STRING  OPTIONAL,                  -> 0xa3
    ...
}

ContextFlags ::= BIT STRING {
    delegFlag       (0),
    mutualFlag      (1),
    replayFlag      (2),
    sequenceFlag    (3),
    anonFlag        (4),
    confFlag        (5),
    integFlag       (6)
} (SIZE (32))

===================================
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

Integrazioni di microsoft:

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
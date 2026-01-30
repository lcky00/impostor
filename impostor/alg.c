// Pseudo code for recursive algorithm for main parser

asn1_obj parse (buffer, len, *ret_len):

    crea asn1_obj
    asn1_obj.type = primo bytes di buffer

    effective_len = estraggo len // len effettiva quindi: 
                                 // - con tag
                                 // - bytes len
                                 // - bytes value
    
    Se asn1_obj.type è una leaf: // non [SEQUNECE, SET, TAG SPNEGO, ...]
        asn1_obj.len = 0
        asn1_obj.list = NULL

        aux_entry = parse in base al tipo
        asn1_obj.entry = nuova entry
        asn1_obj_entry.len = aux_entry.len
        asn1_obj_entry.value = aux_entry.value

        *ret_len = effective_len
        return asn1_obj

    // Se è root [SEQUNECE, SET, TAG SPNEGO, ...]
    asn1_obj.entry = NULL
    asn1_obj.len = 0
    asn1_obj.list = NULL

    offset = tag byte + len bytes

    ret_len = 0

    finche (len-offset) > 0:
        asn1_obj_ret = parse(buffer + offset, effective_len - offset, &ret_len)
        asn1_obj.len = asn1_obj.len + 1
        append(list, asn1_obj_ret)
        //len = len - ret_len

        offset = offset + ret_len
    
    *ret_len = offset
    return asn1_obj


// parse Iterativa
stack_entry = {
        parent_node
        node
        len
        ret_len
    }


int iterative_parse (buffer, len):

    stack = nuovo stack

    tag = primo byte buffer
    
    se tag non valido:
        return errore

    ans1_obj = new asn1_obj

    se è una leaf:
        estraggo dati e popolo asn1_obj.entry
        ritorno obj tramite parametro
        return ok

    len = estraggo length
    popolo asn1_obj.type       

    stack_entry root
    root.parent_node = NULL
    root.node = ans1_obj
    root.len = len
    root.ret_len = 0

    push(stack, root)

    while (stack pieno):

        stack_act = top(stack)

        se tag è una leaf:

            stack_act.ret_len 

        //altrimenti
        calcolo length




        




# Impostor

Server SMB1 per l'intercettazione di Hash NTLMv2, scritto in C.

L'obiettivo del progetto è implementare un server SMB1 come macchina a stati che accetti e risponda correttamente alle richieste del client per ingannarlo, portandolo a completare un'autenticazione NTLM e a rivelare così il proprio hash NTLMv2 (nel formato compatibile con `hashcat`/`john`).

> Strumento pensato per attività di sicurezza offensiva/red teaming e per scopi didattici (studio del protocollo SMB1/NTLM), da usare esclusivamente in ambienti autorizzati e di propria proprietà o con consenso esplicito.

## Come funziona

Il server si finge un server SMB1 legittimo e guida il client lungo una macchina a stati a 3 fasi:

![Schema per macchina a stati](docs/schema.png)

| Stato | Transizione |
|-------|-------------|
| 1. `NEGOTIATE` | Se arriva un `SMB NEGOTIATE`, in seguito alla risposta del server lo stato passa a `2. CHALLENGE` |
| 2. `CHALLENGE` | Se arriva un `NTLM_NEGOTIATE`, in seguito alla risposta del server lo stato passa a `3. AUTH` |
| 3. `AUTH` | Se arriva un `NTLM_AUTH`, in seguito alla risposta del server lo stato torna a `1. NEGOTIATE` |

A livello implementativo va tenuta in considerazione la "busta" esterna NetBIOS, composta da 4 byte, i cui ultimi 3 indicano la lunghezza in byte del pacchetto SMB.

Ogni connessione client è tracciata tramite una struttura di stato (`client_t` in `server.h`) che, oltre allo stato della macchina a stati, mantiene:

- un buffer di ricezione (`rx_buf`) con relativa lunghezza per bufferizzare i dati letti dalla socket ma non ancora completamente processati;
- un buffer di invio (`tx_buf`, con offset `tx_off`) per bufferizzare i dati da inviare al client ma non ancora completamente trasmessi;
- i campi `netbios_header_recv` e `netbios_msg_len` per il tracking dell'header NetBIOS.

Alla ricezione di dati si verifica che almeno **4 byte** (header NetBIOS) siano stati ricevuti, si determina la lunghezza del messaggio SMB, si aggiornano i campi di stato e infine si processa il messaggio, aggiornando lo stato del client per la ricezione successiva.

Il ciclo principale del server si basa su `poll()` per gestire più connessioni contemporaneamente in modo non bloccante:

![Main Loop idea per ricezione](docs/main_loop.png)

Quando l'autenticazione NTLM viene completata, il server stampa a video (`[INTERCEPTED] ...`) username, hostname, dominio e l'hash NTLMv2 catturato, nel formato:

```
username::domain:server_challenge:ntlmv2_response:blob
```

pronto per essere usato con strumenti di cracking come `hashcat` (modalità `-m 5600`) o `john`.

## Struttura del progetto

| File | Descrizione |
|------|-------------|
| `server.c` / `server.h` | Entry point, setup del listener TCP, macchina a stati per client, ciclo principale basato su `poll()`, buffering RX/TX, stampa degli hash intercettati |
| `smb1_parser.c` / `smb1_parser.h` | Parsing/costruzione dei pacchetti SMB1 (header, comandi `NEGOTIATE`, `SESSION_SETUP`, flag/flag2, ecc.) |
| `spnego_decoder.c` / `spnego_decoder.h` | Decodifica del token SPNEGO (negoziazione del meccanismo di autenticazione, estrazione del blob NTLMSSP) contenuto nei messaggi SMB |
| `asn1_parser.c` / `asn1_parser.h` | Parser ASN.1 DER minimale, usato dallo SPNEGO decoder per costruire l'albero della struttura ASN.1 |
| `ntlm_parser.c` / `ntlm_parser.h` | Parsing dei messaggi NTLMSSP (`NEGOTIATE`, `CHALLENGE`, `AUTHENTICATE`) ed estrazione di username, dominio, hostname e risposta NTLMv2 |
| `endianness.h` | Utility per la gestione dell'endianness (conversioni little/big endian a runtime) |
| `test.c`, `test2.c` | File di test/sperimentazione per i parser |
| `docs/` | Diagrammi e materiale di supporto (schema della macchina a stati, main loop) |

## Requisiti

- Compilatore C compatibile con lo standard usato dal progetto (es. `gcc`/`clang`) e toolchain POSIX (il codice utilizza socket BSD, `poll()`, `signal()`, ecc., quindi è pensato per ambienti Linux/Unix-like).


## Compilazione

```sh
gcc -o impostor server.c smb1_parser.c spnego_decoder.c asn1_parser.c ntlm_parser.c
```

## Utilizzo

```sh
./impostor [porta]
```

- `porta` (opzionale): porta TCP su cui il server si mette in ascolto. Se omessa, viene usata la porta di default definita in `server.h` (`SERVER_PORT`, 9000). Deve essere un valore compreso tra 1 e 65535.

All'avvio il server stampa banner, versione e informazioni di configurazione (porta, numero massimo di client), poi resta in ascolto delle connessioni. Alla cattura di un hash NTLMv2, i dati intercettati (username, hostname, dominio, hash) vengono stampati a schermo. Il server può essere arrestato con `Ctrl+C` (`SIGINT`), gestito da `intHandler`.

```
 ___                  ___      _    ___        
|_ _|_ __ ___  _ __  / _ \ ___| |_ / _ \ _ __  
 | || '_ ` _ \| '_ \| | | / __| __| | | | '__| 
 | || | | | | | |_) | |_| \__ \ |_| |_| | |    
|___|_| |_| |_| .__/ \___/|___/\__|\___/|_|    
              |_| (v.1.0)             by Lcky  


[*] Version: 1.0
[*] Author: Lcky <luca9vinci at gmail dot com>

[*] Server Info
    Port: 9090
    Max Clients: 50


[*] Listening on port 9090
[*] Waiting for connections...

[INTERCEPTED] Username: test
[INTERCEPTED] Hostname: KALILINUX-2023-02
[INTERCEPTED] Domain  : WORKGROUP
[INTERCEPTED] Hash    : test::WORKGROUP:c4ba87a265de9e09:3482d0efa64fc09a94e44faa83d2a936:01010000000000009A3DE84B6235DD01D36FD06DFF4D64BB000000000200080038004E004900490001001E00570049004E002D00310046005800340055004D005000530034005400420004003400570049004E002D00310046005800340055004D00500053003400540042002E0038004E00490049002E004C004F00430041004C000300140038004E00490049002E004C004F00430041004C000500140038004E00490049002E004C004F00430041004C0008003000300000000000000000000000000000000CAFEB574B56CB6139E261228FBFE3075B4FA9393A3B71031AF3280F4D5A27D00A0010000000000000000000000000000000000009001C0063006900660073002F003100320037002E0030002E0030002E00310000000000
^C
[*] Stopping the server...
```


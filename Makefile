CC      ?= gcc
CFLAGS  ?= -std=c11 -Wall -Wextra -O2
LDFLAGS ?=

TARGET       := impostor
TEST_TARGET  := test_parser
TEST2_TARGET := test_server_standalone

# Sorgenti del server principale
SRCS := server.c smb1_parser.c spnego_decoder.c asn1_parser.c ntlm_parser.c
OBJS := $(SRCS:.c=.o)

# Sorgenti condivise dai parser
PARSER_SRCS := smb1_parser.c spnego_decoder.c asn1_parser.c ntlm_parser.c
PARSER_OBJS := $(PARSER_SRCS:.c=.o)

.PHONY: all clean test test2 tests run debug

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Target di debug con simboli e sanitizer
debug: CFLAGS += -g -O0 -fsanitize=address,undefined -DDEBUG
debug: clean $(TARGET)

run: $(TARGET)
	./$(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) test.o test2.o $(TARGET) $(TEST_TARGET) $(TEST2_TARGET)
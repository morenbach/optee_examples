CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

CFLAGS += -Wall -I$(TEEC_EXPORT)/include
#Add/link other required libraries here
LDADD += -lteec -L$(TEEC_EXPORT)/lib 
#-lpthread -lunwind-ptrace -lunwind-generic -lboost_system -lcrypto -lssl -lcpprest

SOURCES = main.c \	  
	  tracer_interface.c

OBJS = $(SOURCES:.c=.o)

BINARY = optee_tracer

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS) tracer_interface.h
	$(CC) $(LDFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@



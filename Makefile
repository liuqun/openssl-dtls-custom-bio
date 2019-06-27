CC := gcc
CFLAGS = -g -pthread

OPENSSL_INCLUDE_DIR =
#OPENSSL_INCLUDE_DIR = openssl-1.1.1c/include

OPENSSL_LIB_DIR =
#OPENSSL_LIB_DIR = openssl-1.1.1c/lib

OPENSSL_CFLAGS =
#OPENSSL_CFLAGS = -I$(OPENSSL_INCLUDE_DIR)

OPENSSL_LDFLAGS =
#OPENSSL_LDFLAGS = -L$(OPENSSL_LIB_DIR)

OPENSSL_LIBS = -lssl -lcrypto
# OPENSSL_LIBS = $(OPENSSL_LIB_DIR)/libssl.a $(OPENSLL_LIB_DIR)/libcrypto.a

.PHONY: all clean certs delete-certs

all: server client certs

server: server.o main.o cbio.o util.o
	$(LINK.o) -o $@ $^ -lssl -lcrypto -lpthread
client: client.o cbio.o util.o
	$(LINK.o) -o $@ $^ -lssl -lcrypto -lpthread -lreadline
server client: LDFLAGS+=$(OPENSSL_LDFLAGS)
server.o main.o client.o cbio.o: CFLAGS+=$(OPENSSL_CFLAGS)

certs: root-key.pem root-ca.pem \
server-key.pem server-csr.pem server-cert.pem \
client-key.pem client-csr.pem client-cert.pem

clean: delete-certs
	rm -f *.o server client

delete-certs:
	rm -f *.pem *.srl

%-key.pem:
	openssl ecparam -name secp384r1 -genkey -noout -out $@

%-cert.pem: %-csr.pem root-ca.pem root-key.pem
	openssl x509 -req -in $< -out $@ -CA root-ca.pem -CAkey root-key.pem -days 7

%-csr.pem: %-key.pem
	openssl req -new -key $< -out $@ -subj /CN=test_$*/

root-ca.pem: root-key.pem
	openssl req -new -x509 -nodes -days 7 -key $< -out $@ -subj /CN=test_rootCA/
	test -f root-ca.srl || echo 00 > root-ca.srl


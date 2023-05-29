CC=gcc
CFLAGS=-O2
LIBS=-lcrypto

all: img-sign img-gen

img-sign: img-sign.c
	$(CC) -o img-sign img-sign.c $(CFLAGS) $(LIBS)

img-gen: img-gen.c
	$(CC) -o img-gen ../pem/tiny-asn1.c ../pem/pem-decode.c ../header-gen.c img-gen.c $(CFLAGS) $(LIBS)

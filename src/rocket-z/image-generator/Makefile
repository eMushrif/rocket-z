CC=gcc
CFLAGS=-O2
LIBS=-lcrypto
OUTDIR=build/linux_x86-64

all: img-sign img-gen

img-sign: img-sign.c
	$(CC) -o $(OUTDIR)/img-sign img-sign.c $(CFLAGS) $(LIBS)

img-gen: img-gen.c
	$(CC) -o $(OUTDIR)/img-gen ../pem/tiny-asn1.c ../pem/pem-decode.c ../header-gen.c img-gen.c $(CFLAGS) $(LIBS)

clean:
	rm img-gen img-sign

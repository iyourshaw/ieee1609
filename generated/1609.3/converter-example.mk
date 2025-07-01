include Makefile.am.libasncodec

LIBS += -lm
CFLAGS += $(ASN_MODULE_CFLAGS) -DASN_PDU_COLLECTION -I.
ASN_LIBRARY ?= libasncodec.a
ASN_PROGRAM ?= converter-example
ASN_PROGRAM_SRCS ?= \
	converter-example.c\
	pdu_collection.c

all: $(ASN_PROGRAM)

$(ASN_PROGRAM): $(ASN_LIBRARY) $(ASN_PROGRAM_SRCS:.c=.o)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(ASN_PROGRAM) $(ASN_PROGRAM_SRCS:.c=.o) $(LDFLAGS) $(ASN_LIBRARY) $(LIBS)

$(ASN_LIBRARY): $(ASN_MODULE_SRCS:.c=.o)
	$(AR) rcs $@ $(ASN_MODULE_SRCS:.c=.o)

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(ASN_PROGRAM) $(ASN_LIBRARY)
	rm -f $(ASN_MODULE_SRCS:.c=.o) $(ASN_PROGRAM_SRCS:.c=.o)

regen: regenerate-from-asn1-source

regenerate-from-asn1-source:
	asn1c -fno-include-deps -fcompound-names-all -gen-OER -fincludes-quoted -no-gen-JER -pdu=all ../../asn/1609.3/1609dot2-P2P.asn ../../asn/1609.3/1609dot2-base-types.asn ../../asn/1609.3/1609dot2-schema.asn ../../asn/1609.3/EUTRA-RRC-Definitions.asn ../../asn/1609.3/EUTRA-Sidelink-Preconf.asn ../../asn/1609.3/EtsiTs102941Crl.asn ../../asn/1609.3/Ieee1609Dot3Wee.asn ../../asn/1609.3/Ieee1609Dot3Wsa.asn ../../asn/1609.3/Ieee1609Dot3Wsa1609Dot2Encapsulation.asn ../../asn/1609.3/Ieee1609Dot3WsaSsp.asn ../../asn/1609.3/Ieee1609Dot3Wsm.asn ../../asn/1609.3/crl-base-types.asn ../../asn/1609.3/crl-protocol.asn ../../asn/1609.3/crl-ssp.asn


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
	asn1c -fno-include-deps -fcompound-names-all -gen-OER -fincludes-quoted -pdu=all ../../asn/1609.3-2020/1609dot2-P2P.asn ../../asn/1609.3-2020/1609dot2-base-types.asn ../../asn/1609.3-2020/1609dot2-schema.asn ../../asn/1609.3-2020/EUTRA-RRC-Definitions-Subset.asn ../../asn/1609.3-2020/EUTRA-Sidelink-Preconf-Subset.asn ../../asn/1609.3-2020/EtsiTs102941Crl.asn ../../asn/1609.3-2020/Ieee1609Dot3Wee.asn ../../asn/1609.3-2020/Ieee1609Dot3Wsa.asn ../../asn/1609.3-2020/Ieee1609Dot3Wsa1609Dot2Encapsulation.asn ../../asn/1609.3-2020/Ieee1609Dot3WsaSsp.asn ../../asn/1609.3-2020/Ieee1609Dot3Wsm.asn ../../asn/1609.3-2020/aca-ee.asn ../../asn/1609.3-2020/aca-la.asn ../../asn/1609.3-2020/aca-ma.asn ../../asn/1609.3-2020/aca-ra.asn ../../asn/1609.3-2020/acpc.asn ../../asn/1609.3-2020/cam-ra.asn ../../asn/1609.3-2020/cert-management.asn ../../asn/1609.3-2020/crl-base-types.asn ../../asn/1609.3-2020/crl-protocol.asn ../../asn/1609.3-2020/crl-ssp.asn ../../asn/1609.3-2020/eca-ee.asn ../../asn/1609.3-2020/ee-ma.asn ../../asn/1609.3-2020/ee-ra.asn ../../asn/1609.3-2020/la-ma.asn ../../asn/1609.3-2020/la-ra.asn ../../asn/1609.3-2020/ma-ra.asn ../../asn/1609.3-2020/protocol.asn


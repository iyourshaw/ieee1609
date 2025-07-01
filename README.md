# 1609.3 WAVE Codec 

Codec for IEEE 1609.3 and 1609.2

1609.3: 
* Root PDU is ShortMsgNpdu
* UPER encoded

1609.2: 
  * Root PDU is Ieee1609Dot2Data or Ieee1609Dot2EncapsulatedWsa
  * OER encoded

## Notes

To compile the converter:

### Change the choice field named "NULL" to "NULL_" to avoid conflict with build in NULL C macro in:

* Extensions.h
* Extensions.c
* Ieee1609Dot3Wsa_ExtendedChannelInfo.h
* Ieee1609Dot3Wsa_ExtendedChannelInfo.c

### Edit the 'protocol.asn' file

Use the workaround from this project:
[vanetza ETSI C-ITS implementation](https://github.com/riebl/vanetza)

to deal with the parameterized "WITH COMPONENTS":

https://github.com/riebl/vanetza/blob/6eb42c644d367a7871705b4e3d27c9f71c435d9d/vanetza/asn1/patches/ieee/Ieeedot2dot1Protocol.patch

Patch file:

[asn/1609.3-2020/protocol.patch](asn/1609.3-2020/protocol.patch)

---

Compile

```bash
asn1c -fno-include-deps -fcompound-names-all -gen-OER -fincludes-quoted -pdu=all ../../asn/1609.3-2020/*.asn
```
or
```bash
asn1c -fno-include-deps -fcompound-names-all -gen-OER -fincludes-quoted -pdu=auto ../../asn/1609.3-2020/*.asn
```
---

Logical Link Control EtherType = 0x88DC

EtherTypes: https://standards-oui.ieee.org/ethertype/eth.txt

0x88DC = (WAVE) Short Message Protocol (WSM) 

see comment in Wireshark dissector in packet-llc.c:

	/* IEEE 1609.3 Ch 5.2.1
	 * The LLC sublayer header consists solely of a 2-octet field
	* that contains an EtherType that identifies the higher layer protocol...
	* Check for 0x86DD too?
	*/

0x86DD = Internet Protocol Version 6 (IPV6)

---

Files `EUTRA-RRC-Definitions.asn` and `EUTRA-Sidelink-Preconf.asn` files are copied from the Wireshark dissectors.
They contain more than is needed, should extract only the imported PDUs to reduce bloat.

---

The 1609.3 specification is from 2020.  It depends on and older version of 1609.2 
(it doesn't work with the 1609.2-2022 OID)

---

To decode from a PCAP frame (802.11/radiotap), extract everything after the 
0x86DD marker into file `ShortMsgData.bin`.

Decode 1609.3:
```bash
./converter-example -p ShortMsgNpdu -iuper -oxer -1 ShortMsgNpdu.bin > ShortMsgNpdu.xml
```

or 

```bash
./converter-example-jer -p ShortMsgNpdu -iuper -ojer -1 ShortMsgNpdu.bin
```

Extract the hex from the `body` element, convert to bin in `ShortMsgData.bin`, Decode 1609.2 via:
```bash
./converter-example -p Ieee1609Dot2Data -ioer -oxer ShortMsgData.bin > ShortMsgData.xml
```
or
```bash
./converter-example -p Ieee1609Dot2EncapsulatedWsa -ioer -oxer -1 ShortMsgData.bin
```

---

UDP from PCAP

Remove initial byte 01 from the UDP payload, then decode ShortMsgNpdu
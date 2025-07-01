# ASN.1 module Ieee1609Dot2Peer2Peer
 OID: _{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) management(2) peer-to-peer(1) major-version-2(2) minor-version-3(3)}_
 @note Section references in this file are to clauses in IEEE Std
 1609.2 unless indicated otherwise. Full forms of acronyms and
 abbreviations used in this file are specified in 3.2.


## Imports:
 * **[Ieee1609Dot2](Ieee1609Dot2.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) schema(1) major-version-2(2) minor-version-6(6)} WITH SUCCESSORS*<br/>

 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="Ieee1609dot2Peer2PeerPDU"></a>Ieee1609dot2Peer2PeerPDU

 The fields in this structure have the following meaning:

Fields:
* version [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) (1)<br>
is the version number of this structure. For this version
 of this standard it is 1.

* content [**CHOICE**](#CHOICE)  {
    caCerts CaCertP2pPDU,
    ...
  }<br>
contains the following:
   - The choice caCerts is indicated.
   - The caCerts field contains an array of certificates, such that:
     - Each certificate is issued by the next certificate in the array.
     - The first certificate in the array is the one indicated by the
 p2pcdLearningRequest value mci to which the response message is responding
 (see 8.4.2).
     - The final certificate in the array was issued by a root CA.

```asn1
Ieee1609dot2Peer2PeerPDU ::= SEQUENCE {
  version Uint8(1),
  content CHOICE {
    caCerts CaCertP2pPDU,
    ...
  }
}
```

### <a name="CaCertP2pPDU"></a>CaCertP2pPDU

 This type is used for clarity of definitions.



```asn1
CaCertP2pPDU ::= SEQUENCE OF Certificate
```




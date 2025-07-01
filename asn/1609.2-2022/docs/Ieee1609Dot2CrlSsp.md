# ASN.1 module Ieee1609Dot2CrlSsp
 OID: _{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) crl(3) ssp(3) major-version-2(2) minor-version-2(2)}_
 @note Section references in this file are to clauses in IEEE Std
 1609.2 unless indicated otherwise. Full forms of acronyms and
 abbreviations used in this file are specified in 3.2.


## Imports:
 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="CrlSsp"></a>CrlSsp

 In this structure:

Fields:
* version [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) (1)<br>
is the version number of the SSP and is 1 for this version
 of the SSP.

* associatedCraca [**CracaType**](#CracaType) <br>
identifies the relationship between this
 certificate and the CRACA. If associatedCraca = isCraca, this certificate
 is the CRACA certificate and signs CRLs for certificates which chain back
 to this certificate. If associatedCraca = issuerIsCraca, the issuer of
 this certificate is the CRACA and this certificate may sign CRLs for
 certificates which chain back to its issuer.

* crls [**PermissibleCrls**](#PermissibleCrls) <br>
identifies what type of CRLs may be issued by the certificate
 holder.

```asn1
CrlSsp::= SEQUENCE {
  version         Uint8(1),
  associatedCraca CracaType,
  crls            PermissibleCrls,
  ...
}
```

### <a name="CracaType"></a>CracaType

 This type is used to determine the validity of the crlCraca field
 in the CrlContents structure.
   - If this takes the value isCraca, the crlCraca field in the CrlContents
 structure is invalid unless it indicates the certificate that signs the
 CRL.
   - If this takes the value issuer, the isCracaDelegate field in the
 CrlContents structure is invalid unless it indicates the certificate that
 issued the certificate that signs the CRL.



```asn1
CracaType ::= ENUMERATED {isCraca, issuerIsCraca}
```

### <a name="PermissibleCrls"></a>PermissibleCrls

 This type is used to determine the validity of the crlSeries field
 in the CrlContents structure. The crlSeries field in the CrlContents
 structure is invalid unless that value appears as an entry in the
 SEQUENCE contained in this field.



```asn1
PermissibleCrls ::= SEQUENCE OF CrlSeries
```




# ASN.1 module Ieee1609Dot2Crl
 OID: _{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) crl(3) major-version-3(3) minor-version-2(2)}_
 @note Section references in this file are to clauses in IEEE Std
 1609.2 unless indicated otherwise. Full forms of acronyms and
 abbreviations used in this file are specified in 3.2.


## Imports:
 * **[Ieee1609Dot2](Ieee1609Dot2.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) schema(1) major-version-2(2) minor-version-6(6)} WITH SUCCESSORS*<br/>

 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

 * **[Ieee1609Dot2CrlBaseTypes](Ieee1609Dot2CrlBaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) crl(3) base-types(2) major-version-3(3) minor-version-2(2)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="CrlPsid"></a>CrlPsid

 This is the PSID for the CRL application.



```asn1
CrlPsid ::= Psid(256)
```

### <a name="SecuredCrl"></a>SecuredCrl

 This structure is the SPDU used to contain a signed CRL. A valid
 signed CRL meets the validity criteria of 7.4.



```asn1
SecuredCrl ::= Ieee1609Dot2Data (WITH COMPONENTS {..., 
  content (WITH COMPONENTS {
    signedData  (WITH COMPONENTS {..., 
      tbsData (WITH COMPONENTS {
        payload (WITH COMPONENTS {..., 
          data (WITH COMPONENTS {...,
             content (WITH COMPONENTS {
                unsecuredData (CONTAINING CrlContents)
            })
          })
        }),
        headerInfo (WITH COMPONENTS {..., 
          psid (CrlPsid),
          generationTime ABSENT,
          expiryTime ABSENT,
          generationLocation ABSENT,
          p2pcdLearningRequest ABSENT,
          missingCrlIdentifier ABSENT,
          encryptionKey ABSENT
        })
      })
    })
  })
})
```




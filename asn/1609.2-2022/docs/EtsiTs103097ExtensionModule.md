# ASN.1 module EtsiTs103097ExtensionModule
 OID: _{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) major-version-1(1) minor-version-0(0)}_

## Imports:
 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="ExtensionModuleVersion"></a>ExtensionModuleVersion

```asn1
ExtensionModuleVersion ::= INTEGER(1)
```

### <a name="EtsiOriginatingHeaderInfoExtension"></a>EtsiOriginatingHeaderInfoExtension

```asn1
EtsiOriginatingHeaderInfoExtension ::= 
  Extension{{EtsiTs103097HeaderInfoExtensions}}
```

### <a name="EtsiTs103097HeaderInfoExtensionId"></a>EtsiTs103097HeaderInfoExtensionId

```asn1
EtsiTs103097HeaderInfoExtensionId ::= ExtId
   etsiTs102941CrlRequestId      EtsiTs103097HeaderInfoExtensionId ::= 1
   etsiTs102941DeltaCtlRequestId EtsiTs103097HeaderInfoExtensionId ::= 2
```

### <a name="EtsiTs103097HeaderInfoExtensions"></a>EtsiTs103097HeaderInfoExtensions

```asn1
EtsiTs103097HeaderInfoExtensions EXT-TYPE ::= {
   { EtsiTs102941CrlRequest      IDENTIFIED BY etsiTs102941CrlRequestId } |
   { EtsiTs102941DeltaCtlRequest IDENTIFIED BY etsiTs102941DeltaCtlRequestId },
   ...
}
```

### <a name="EtsiTs102941CrlRequest"></a>EtsiTs102941CrlRequest

```asn1
EtsiTs102941CrlRequest ::= NULL
```

### <a name="EtsiTs102941CtlRequest"></a>EtsiTs102941CtlRequest

```asn1
EtsiTs102941CtlRequest ::= NULL
```

### <a name="EtsiTs102941DeltaCtlRequest"></a>EtsiTs102941DeltaCtlRequest

```asn1
EtsiTs102941DeltaCtlRequest ::= EtsiTs102941CtlRequest
```




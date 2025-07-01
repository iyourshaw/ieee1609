# ASN.1 module Ieee1609Dot2CrlBaseTypes
 OID: _{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) crl(3) base-types(2) major-version-3(3) minor-version-2(2)}_
 @note Section references in this file are to clauses in IEEE Std
 1609.2 unless indicated otherwise. Full forms of acronyms and
 abbreviations used in this file are specified in 3.2.


## Imports:
 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="CrlContents"></a>CrlContents

 The fields in this structure have the following meaning:

Fields:
* version [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8)  (1)<br>
is the version number of the CRL. For this version of this
 standard it is 1.

* crlSeries [**CrlSeries**](Ieee1609Dot2BaseTypes.md#CrlSeries) <br>
represents the CRL series to which this CRL belongs. This
 is used to determine whether the revocation information in a CRL is relevant
 to a particular certificate as specified in 5.1.3.2.

* crlCraca [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
contains the low-order eight octets of the hash of the
 certificate of the Certificate Revocation Authorization CA (CRACA) that
 ultimately authorized the issuance of this CRL. This is used to determine
 whether the revocation information in a CRL is relevant to a particular
 certificate as specified in 5.1.3.2. In a valid signed CRL as specified in
 7.4 the crlCraca is consistent with the associatedCraca field in the
 Service Specific Permissions as defined in 7.4.3.3. The HashedId8 is
 calculated with the whole-certificate hash algorithm, determined as
 described in 6.4.3, applied to the COER-encoded certificate, canonicalized
 as defined in the definition of Certificate.

* issueDate [**Time32**](Ieee1609Dot2BaseTypes.md#Time32) <br>
specifies the time when the CRL was issued.

* nextCrl [**Time32**](Ieee1609Dot2BaseTypes.md#Time32) <br>
contains the time when the next CRL with the same crlSeries
 and cracaId is expected to be issued. The CRL is invalid unless nextCrl is
 strictly after issueDate. This field is used to set the expected update time
 for revocation information associated with the (crlCraca, crlSeries) pair as
 specified in 5.1.3.6.

* priorityInfo [**CrlPriorityInfo**](#CrlPriorityInfo) <br>
contains information that assists devices with limited
 storage space in determining which revocation information to retain and
 which to discard.

* typeSpecific [**TypeSpecificCrlContents**](#TypeSpecificCrlContents) <br>
contains the CRL body.

```asn1
CrlContents ::= SEQUENCE {
  version      Uint8 (1),
  crlSeries    CrlSeries,
  crlCraca     HashedId8,
  issueDate    Time32,   
  nextCrl      Time32,  
  priorityInfo CrlPriorityInfo,
  typeSpecific TypeSpecificCrlContents
}
```

### <a name="CrlPriorityInfo"></a>CrlPriorityInfo

 This data structure contains information that assists devices with
 limited storage space in determining which revocation information to retain
 and which to discard.

 @note This mechanism is for future use; details are not specified in this
 version of the standard.

Fields:
* priority [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8)  OPTIONAL<br>
indicates the priority of the revocation information
 relative to other CRLs issued for certificates with the same cracaId and
 crlSeries values. A higher value for this field indicates higher importance
 of this revocation information.

```asn1
CrlPriorityInfo ::= SEQUENCE {  
  priority Uint8 OPTIONAL,
  ...
}
```

### <a name="TypeSpecificCrlContents"></a>TypeSpecificCrlContents

 This structure contains type-specific CRL contents.

 @note It is the intent of this standard that once a certificate is revoked,
 it remains revoked for the rest of its lifetime. CRL signers are expected
 to include a revoked certificate on all CRLs issued between the
 certificate's revocation and its expiry.

 @note Seed evolution function and linkage value generation function
 identification. In order to derive linkage values per the mechanisms given
 in 5.1.3.4, a receiver needs to know the seed evolution function and the
 linkage value generation function.

 If the contents of this structure is a
 ToBeSignedLinkageValueCrlWithAlgIdentifier, then the seed evolution function
 and linkage value generation function are given explicitly as specified in
 the specification of ToBeSignedLinkageValueCrlWithAlgIdentifier.

 If the contents of this structure is a ToBeSignedLinkageValueCrl, then the
 seed evolution function and linkage value generation function are obtained
 based on the crlCraca field in the CrlContents:
  - If crlCraca was obtained with SHA-256 or SHA-384, then
 seedEvolutionFunctionIdentifier is seedEvoFn1-sha256 and
 linkageValueGenerationFunctionIdentifier is lvGenFn1-aes128.
  - If crlCraca was obtained with SM3, then seedEvolutionFunctionIdentifier
 is seedEvoFn1-sm3 and linkageValueGenerationFunctionIdentifier is
 lvGenFn1-sm4.

Fields:
* fullHashCrl [**ToBeSignedHashIdCrl**](#ToBeSignedHashIdCrl) <br>
contains a full hash-based CRL, i.e., a listing of the
 hashes of all certificates that:
  - contain the indicated cracaId and crlSeries values, and
  - are revoked by hash, and
  - have been revoked, and
  - have not expired.

* deltaHashCrl [**ToBeSignedHashIdCrl**](#ToBeSignedHashIdCrl) <br>
contains a delta hash-based CRL, i.e., a listing of
 the hashes of all certificates that:
  - contain the indicated cracaId and crlSeries values, and
  - are revoked by hash, and
  - have been revoked since the previous CRL that contained the indicated
 cracaId and crlSeries values.

* fullLinkedCrl [**ToBeSignedLinkageValueCrl**](#ToBeSignedLinkageValueCrl) <br>
and fullLinkedCrlWithAlg: contain a full linkage
 ID-based CRL, i.e., a listing of the individual and/or group linkage data
 for all certificates that:
  - contain the indicated cracaId and crlSeries values, and
  - are revoked by linkage value, and
  - have been revoked, and
  - have not expired.
 The difference between fullLinkedCrl and fullLinkedCrlWithAlg is in how
 the cryptographic algorithms to be used in the seed evolution function and
 linkage value generation function of 5.1.3.4 are communicated to the
 receiver of the CRL. See below in this subclause for details.

* deltaLinkedCrl [**ToBeSignedLinkageValueCrl**](#ToBeSignedLinkageValueCrl) <br>
and deltaLinkedCrlWithAlg: contain a delta linkage
 ID-based CRL, i.e., a listing of the individual and/or group linkage data
 for all certificates that:
  - contain the specified cracaId and crlSeries values, and
  -	are revoked by linkage data, and
  -	have been revoked since the previous CRL that contained the indicated
 cracaId and crlSeries values.
 The difference between deltaLinkedCrl and deltaLinkedCrlWithAlg is in how
 the cryptographic algorithms to be used in the seed evolution function
 and linkage value generation function of 5.1.3.4 are communicated to the
 receiver of the CRL. See below in this subclause for details.

* fullLinkedCrlWithAlg [**ToBeSignedLinkageValueCrlWithAlgIdentifier**](#ToBeSignedLinkageValueCrlWithAlgIdentifier) <br>
* deltaLinkedCrlWithAlg [**ToBeSignedLinkageValueCrlWithAlgIdentifier**](#ToBeSignedLinkageValueCrlWithAlgIdentifier) <br>
```asn1
TypeSpecificCrlContents ::= CHOICE {
  fullHashCrl           ToBeSignedHashIdCrl,            
  deltaHashCrl          ToBeSignedHashIdCrl,            
  fullLinkedCrl         ToBeSignedLinkageValueCrl,
  deltaLinkedCrl        ToBeSignedLinkageValueCrl,
  ...,
  fullLinkedCrlWithAlg  ToBeSignedLinkageValueCrlWithAlgIdentifier,
  deltaLinkedCrlWithAlg ToBeSignedLinkageValueCrlWithAlgIdentifier
}
```

### <a name="ToBeSignedHashIdCrl"></a>ToBeSignedHashIdCrl

 This data structure represents information about a revoked
 certificate.

 @note To indicate that a hash-based CRL contains no individual revocation
 information items, the recommended approach is for the SEQUENCE OF in the
 SequenceOfHashBasedRevocationInfo in this field to indicate zero entries.

Fields:
* crlSerial [**Uint32**](Ieee1609Dot2BaseTypes.md#Uint32) <br>
is a counter that increments by 1 every time a new full
 or delta CRL is issued for the indicated crlCraca and crlSeries values.

* entries [**SequenceOfHashBasedRevocationInfo**](#SequenceOfHashBasedRevocationInfo) <br>
contains the individual revocation information items.

```asn1
ToBeSignedHashIdCrl ::= SEQUENCE {  
  crlSerial Uint32,
  entries   SequenceOfHashBasedRevocationInfo,
  ...
}
```

### <a name="SequenceOfHashBasedRevocationInfo"></a>SequenceOfHashBasedRevocationInfo

 This type is used for clarity of definitions.



```asn1
SequenceOfHashBasedRevocationInfo ::= 
  SEQUENCE OF HashBasedRevocationInfo
```

### <a name="HashBasedRevocationInfo"></a>HashBasedRevocationInfo

 In this structure:

Fields:
* id [**HashedId10**](Ieee1609Dot2BaseTypes.md#HashedId10) <br>
is the HashedId10 identifying the revoked certificate. The
 HashedId10 is calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3, applied to the COER-encoded certificate,
 canonicalized as defined in the definition of Certificate.

* expiry [**Time32**](Ieee1609Dot2BaseTypes.md#Time32) <br>
is the value computed from the validity period's start and
 duration values in that certificate.

```asn1
HashBasedRevocationInfo ::= SEQUENCE {
  id     HashedId10,
  expiry Time32,
  ...
}
```

### <a name="ToBeSignedLinkageValueCrl"></a>ToBeSignedLinkageValueCrl

 In this structure:

 @note To indicate that a linkage ID-based CRL contains no individual
 linkage data, the recommended approach is for the SEQUENCE OF in the
 SequenceOfJMaxGroup in this field to indicate zero entries.

 @note To indicate that a linkage ID-based CRL contains no group linkage
 data, the recommended approach is for the SEQUENCE OF in the
 SequenceOfGroupCrlEntry in this field to indicate zero entries.

Fields:
* iRev [**IValue**](Ieee1609Dot2BaseTypes.md#IValue) <br>
is the value iRev used in the algorithm given in 5.1.3.4. This
 value applies to all linkage-based revocation information included within
 either indvidual or groups.

* indexWithinI [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) <br>
is a counter that is set to 0 for the first CRL issued
 for the indicated combination of crlCraca, crlSeries, and iRev, and
 increments by 1 every time a new full or delta CRL is issued for the
 indicated crlCraca and crlSeries values without changing iRev.

* individual [**SequenceOfJMaxGroup**](#SequenceOfJMaxGroup)  OPTIONAL<br>
contains individual linkage data.

* groups [**SequenceOfGroupCrlEntry**](#SequenceOfGroupCrlEntry)  OPTIONAL<br>
contains group linkage data.

* groupsSingleSeed [**SequenceOfGroupSingleSeedCrlEntry**](#SequenceOfGroupSingleSeedCrlEntry)  OPTIONAL<br>
contains group linkage data generated with a single
 seed.

```asn1
ToBeSignedLinkageValueCrl ::= SEQUENCE {  
  iRev             IValue,
  indexWithinI     Uint8,
  individual       SequenceOfJMaxGroup OPTIONAL,
  groups           SequenceOfGroupCrlEntry OPTIONAL,
  ...,
  groupsSingleSeed SequenceOfGroupSingleSeedCrlEntry OPTIONAL
} (WITH COMPONENTS {..., individual PRESENT} |
   WITH COMPONENTS {..., groups PRESENT} |
   WITH COMPONENTS {..., groupsSingleSeed PRESENT})
```

### <a name="SequenceOfJMaxGroup"></a>SequenceOfJMaxGroup

 This type is used for clarity of definitions.



```asn1
SequenceOfJMaxGroup ::= SEQUENCE OF JMaxGroup
```

### <a name="JMaxGroup"></a>JMaxGroup

 In this structure:

Fields:
* jmax [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) <br>
* contents [**SequenceOfLAGroup**](#SequenceOfLAGroup) <br>
contains individual linkage data.

```asn1
JMaxGroup ::= SEQUENCE {
  jmax     Uint8,
  contents SequenceOfLAGroup,
  ...
}
```

### <a name="SequenceOfLAGroup"></a>SequenceOfLAGroup

 This type is used for clarity of definitions.



```asn1
SequenceOfLAGroup ::= SEQUENCE OF LAGroup
```

### <a name="LAGroup"></a>LAGroup

 In this structure:

Fields:
* la1Id [**LaId**](Ieee1609Dot2BaseTypes.md#LaId) <br>
is the value LinkageAuthorityIdentifier1 used in the
 algorithm given in 5.1.3.4. This value applies to all linkage-based
 revocation information included within contents.

* la2Id [**LaId**](Ieee1609Dot2BaseTypes.md#LaId) <br>
is the value LinkageAuthorityIdentifier2 used in the
 algorithm given in 5.1.3.4. This value applies to all linkage-based
 revocation information included within contents.

* contents [**SequenceOfIMaxGroup**](#SequenceOfIMaxGroup) <br>
contains individual linkage data.

```asn1
LAGroup ::= SEQUENCE {
  la1Id    LaId,
  la2Id    LaId,
  contents SequenceOfIMaxGroup,
  ...
}
```

### <a name="SequenceOfIMaxGroup"></a>SequenceOfIMaxGroup

 This type is used for clarity of definitions.



```asn1
SequenceOfIMaxGroup ::= SEQUENCE OF IMaxGroup
```

### <a name="IMaxGroup"></a>IMaxGroup

 In this structure:

Fields:
* iMax [**Uint16**](Ieee1609Dot2BaseTypes.md#Uint16) <br>
indicates that for the entries in contents, revocation
 information need no longer be calculated once iCert > iMax as the holder
 is known to have no more valid certs at that point. iMax is not directly
 used in the calculation of the linkage values, it is used to determine
 when revocation information can safely be deleted.

* contents [**SequenceOfIndividualRevocation**](#SequenceOfIndividualRevocation) <br>
contains individual linkage data for certificates that are
 revoked using two seeds, per the algorithm given in per the mechanisms
 given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and
 linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3.

* singleSeed [**SequenceOfLinkageSeed**](Ieee1609Dot2BaseTypes.md#SequenceOfLinkageSeed)  OPTIONAL<br>
contains individual linkage data for certificates that
 are revoked using a single seed, per the algorithm given in per the
 mechanisms given in 5.1.3.4 and with seedEvolutionFunctionIdentifier and
 linkageValueGenerationFunctionIdentifier obtained as specified in 7.3.3.

```asn1
IMaxGroup ::= SEQUENCE {
  iMax       Uint16,
  contents   SequenceOfIndividualRevocation,
  ...,
  singleSeed SequenceOfLinkageSeed OPTIONAL
}
```

### <a name="SequenceOfIndividualRevocation"></a>SequenceOfIndividualRevocation

 This type is used for clarity of definitions.



```asn1
SequenceOfIndividualRevocation ::= 
  SEQUENCE (SIZE(0..MAX)) OF IndividualRevocation
```

### <a name="IndividualRevocation"></a>IndividualRevocation

 In this structure:

Fields:
* linkageSeed1 [**LinkageSeed**](Ieee1609Dot2BaseTypes.md#LinkageSeed) <br>
is the value LinkageSeed1 used in the algorithm given
 in 5.1.3.4.

* linkageSeed2 [**LinkageSeed**](Ieee1609Dot2BaseTypes.md#LinkageSeed) <br>
is the value LinkageSeed2 used in the algorithm given
 in 5.1.3.4.

```asn1
IndividualRevocation ::= SEQUENCE { 
  linkageSeed1 LinkageSeed,
  linkageSeed2 LinkageSeed,
  ...
}
```

### <a name="SequenceOfGroupCrlEntry"></a>SequenceOfGroupCrlEntry

 This type is used for clarity of definitions.



```asn1
SequenceOfGroupCrlEntry ::= SEQUENCE OF GroupCrlEntry
```

### <a name="GroupCrlEntry"></a>GroupCrlEntry

 In this structure:

Fields:
* iMax [**Uint16**](Ieee1609Dot2BaseTypes.md#Uint16) <br>
indicates that for these certificates, revocation information
 need no longer be calculated once iCert > iMax as the holders are known
 to have no more valid certs for that (crlCraca, crlSeries) at that point.

* la1Id [**LaId**](Ieee1609Dot2BaseTypes.md#LaId) <br>
is the value LinkageAuthorityIdentifier1 used in the
 algorithm given in 5.1.3.4. This value applies to all linkage-based
 revocation information included within contents.

* linkageSeed1 [**LinkageSeed**](Ieee1609Dot2BaseTypes.md#LinkageSeed) <br>
is the value LinkageSeed1 used in the algorithm given
 in 5.1.3.4.

* la2Id [**LaId**](Ieee1609Dot2BaseTypes.md#LaId) <br>
is the value LinkageAuthorityIdentifier2 used in the
 algorithm given in 5.1.3.4. This value applies to all linkage-based
 revocation information included within contents.

* linkageSeed2 [**LinkageSeed**](Ieee1609Dot2BaseTypes.md#LinkageSeed) <br>
is the value LinkageSeed2 used in the algorithm given
 in 5.1.3.4.

```asn1
GroupCrlEntry ::= SEQUENCE {
  iMax         Uint16,
  la1Id        LaId,
  linkageSeed1 LinkageSeed,
  la2Id        LaId,
  linkageSeed2 LinkageSeed,
  ...
}
```

### <a name="ToBeSignedLinkageValueCrlWithAlgIdentifier"></a>ToBeSignedLinkageValueCrlWithAlgIdentifier

 In this structure:

Fields:
* iRev [**IValue**](Ieee1609Dot2BaseTypes.md#IValue) <br>
is the value iRev used in the algorithm given in 5.1.3.4. This
 value applies to all linkage-based revocation information included within
 either indvidual or groups.

* indexWithinI [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) <br>
is a counter that is set to 0 for the first CRL issued
 for the indicated combination of crlCraca, crlSeries, and iRev, and increments by 1 every time a new full or delta CRL is issued for the indicated crlCraca and crlSeries values without changing iRev.

* seedEvolution [**SeedEvolutionFunctionIdentifier**](#SeedEvolutionFunctionIdentifier) <br>
contains an identifier for the seed evolution
 function, used as specified in  5.1.3.4.

* lvGeneration [**LvGenerationFunctionIdentifier**](#LvGenerationFunctionIdentifier) <br>
contains an identifier for the linkage value
 generation function, used as specified in  5.1.3.4.

* individual [**SequenceOfJMaxGroup**](#SequenceOfJMaxGroup)  OPTIONAL<br>
contains individual linkage data.

* groups [**SequenceOfGroupCrlEntry**](#SequenceOfGroupCrlEntry)  OPTIONAL<br>
contains group linkage data for linkage value generation
 with two seeds.

* groupsSingleSeed [**SequenceOfGroupSingleSeedCrlEntry**](#SequenceOfGroupSingleSeedCrlEntry)  OPTIONAL<br>
contains group linkage data for linkage value
 generation with one seed.

```asn1
ToBeSignedLinkageValueCrlWithAlgIdentifier ::= SEQUENCE {  
  iRev             IValue,
  indexWithinI     Uint8,
  seedEvolution    SeedEvolutionFunctionIdentifier,
  lvGeneration     LvGenerationFunctionIdentifier,
  individual       SequenceOfJMaxGroup OPTIONAL,
  groups           SequenceOfGroupCrlEntry OPTIONAL,
  groupsSingleSeed SequenceOfGroupSingleSeedCrlEntry OPTIONAL,
  ...
} (WITH COMPONENTS {..., individual PRESENT} |
   WITH COMPONENTS {..., groups PRESENT} |
   WITH COMPONENTS {..., groupsSingleSeed PRESENT})
```

### <a name="SequenceOfGroupSingleSeedCrlEntry"></a>SequenceOfGroupSingleSeedCrlEntry

 This type is used for clarity of definitions.



```asn1
SequenceOfGroupSingleSeedCrlEntry ::= 
  SEQUENCE OF GroupSingleSeedCrlEntry
```

### <a name="GroupSingleSeedCrlEntry"></a>GroupSingleSeedCrlEntry

 This structure contains the linkage seed for group revocation with
 a single seed. The seed is used as specified in the algorithms in 5.1.3.4.

Fields:
* iMax [**Uint16**](Ieee1609Dot2BaseTypes.md#Uint16) <br>
* laId [**LaId**](Ieee1609Dot2BaseTypes.md#LaId) <br>
* linkageSeed [**LinkageSeed**](Ieee1609Dot2BaseTypes.md#LinkageSeed) <br>
```asn1
GroupSingleSeedCrlEntry ::= SEQUENCE {
  iMax        Uint16,
  laId        LaId,
  linkageSeed LinkageSeed
}
```

### <a name="ExpansionAlgorithmIdentifier"></a>ExpansionAlgorithmIdentifier

 This structure contains an identifier for the algorithms specified
 in 5.1.3.4.



```asn1
ExpansionAlgorithmIdentifier ::= ENUMERATED {
  sha256ForI-aesForJ,
  sm3ForI-sm4ForJ,
  ...
}
```

### <a name="SeedEvolutionFunctionIdentifier"></a>SeedEvolutionFunctionIdentifier

 This is the identifier for the seed evolution function. See 5.1.3
 for details of use.



```asn1
SeedEvolutionFunctionIdentifier ::= NULL
```

### <a name="LvGenerationFunctionIdentifier"></a>LvGenerationFunctionIdentifier

 This is the identifier for the linkage value generation function.
 See 5.1.3 for details of use.



```asn1
LvGenerationFunctionIdentifier ::= NULL
```




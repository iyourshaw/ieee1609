# ASN.1 module Ieee1609Dot2
 OID: _{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) schema(1) major-version-2(2) minor-version-6(6)}_
 @note Section references in this file are to clauses in IEEE Std
 1609.2 unless indicated otherwise. Full forms of acronyms and
 abbreviations used in this file are specified in 3.2.


## Imports:
 * **[Ieee1609Dot2BaseTypes](Ieee1609Dot2BaseTypes.md)** *{iso(1) identified-organization(3) ieee(111) standards-association-numbered-series-standards(2) wave-stds(1609) dot2(2) base(1) base-types(2) major-version-2(2) minor-version-4(4)} WITH SUCCESSORS*<br/>

 * **[EtsiTs103097ExtensionModule](EtsiTs103097ExtensionModule.md)** *{itu-t(0) identified-organization(4) etsi(0) itsDomain(5) wg5(5) secHeaders(103097) extension(2) major-version-1(1) minor-version-0(0)} WITH SUCCESSORS*<br/>

## Data Elements:
### <a name="Ieee1609Dot2Data"></a>Ieee1609Dot2Data

 This data type is used to contain the other data types in this
 clause. The fields in the Ieee1609Dot2Data have the following meanings:

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the Ieee1609Dot2Content.

Fields:
* protocolVersion [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) (3)<br>
contains the current version of the protocol. The
 version specified in this standard is version 3, represented by the
 integer 3. There are no major or minor version numbers.

* content [**Ieee1609Dot2Content**](#Ieee1609Dot2Content) <br>
contains the content in the form of an Ieee1609Dot2Content.

```asn1
Ieee1609Dot2Data ::= SEQUENCE {
  protocolVersion Uint8(3),
  content         Ieee1609Dot2Content
}
```

### <a name="Ieee1609Dot2Content"></a>Ieee1609Dot2Content

 In this structure:

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2 if it is of type signedData.
 The canonicalization applies to the SignedData.

Fields:
* unsecuredData [**Opaque**](Ieee1609Dot2BaseTypes.md#Opaque) <br>
indicates that the content is an OCTET STRING to be
 consumed outside the SDS.

* signedData [**SignedData**](#SignedData) <br>
indicates that the content has been signed according to
 this standard.

* encryptedData [**EncryptedData**](#EncryptedData) <br>
indicates that the content has been encrypted
 according to this standard.

* signedCertificateRequest [**Opaque**](Ieee1609Dot2BaseTypes.md#Opaque) <br>
indicates that the content is a
 certificate request signed by an IEEE 1609.2 certificate or self-signed.

* signedX509CertificateRequest [**Opaque**](Ieee1609Dot2BaseTypes.md#Opaque) <br>
indicates that the content is a
 certificate request signed by an ITU-T X.509 certificate.

```asn1
Ieee1609Dot2Content ::=  CHOICE { 
  unsecuredData                Opaque, 
  signedData                   SignedData,
  encryptedData                EncryptedData,
  signedCertificateRequest     Opaque,
  ...,
  signedX509CertificateRequest Opaque
}
```

### <a name="SignedData"></a>SignedData

 In this structure:

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the ToBeSignedData and the Signature.

Fields:
* hashId [**HashAlgorithm**](Ieee1609Dot2BaseTypes.md#HashAlgorithm) <br>
indicates the hash algorithm to be used to generate the hash
 of the message for signing and verification.

* tbsData [**ToBeSignedData**](#ToBeSignedData) <br>
contains the data that is hashed as input to the signature.

* signer [**SignerIdentifier**](#SignerIdentifier) <br>
determines the keying material and hash algorithm used to
 sign the data.

* signature [**Signature**](Ieee1609Dot2BaseTypes.md#Signature) <br>
contains the digital signature itself, calculated as
 specified in 5.3.1.
   - If signer indicates the choice self, then the signature calculation
 is parameterized as follows:
     - Data input is equal to the COER encoding of the tbsData field
 canonicalized according to the encoding considerations given in 6.3.6.
     - Verification type is equal to self.
     - Signer identifier input is equal to the empty string.
   - If signer indicates certificate or digest, then the signature
 calculation is parameterized as follows:
     - Data input is equal to the COER encoding of the tbsData field
 canonicalized according to the encoding considerations given in 6.3.6.
     - Verification type is equal to certificate.
     - Signer identifier input equal to the COER-encoding of the
 Certificate that is to be used to verify the SPDU, canonicalized according
 to the encoding considerations given in 6.4.3.

```asn1
SignedData ::= SEQUENCE { 
  hashId    HashAlgorithm,
  tbsData   ToBeSignedData,
  signer    SignerIdentifier,
  signature Signature
}
```

### <a name="ToBeSignedData"></a>ToBeSignedData

 This structure contains the data to be hashed when generating or
 verifying a signature. See 6.3.4 for the specification of the input to the
 hash.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the SignedDataPayload if it is of type data, and to the
 HeaderInfo.

Fields:
* payload [**SignedDataPayload**](#SignedDataPayload) <br>
contains data that is provided by the entity that invokes
 the SDS.

* headerInfo [**HeaderInfo**](#HeaderInfo) <br>
contains additional data that is inserted by the SDS.
 This structure is used as follows to determine the "data input" to the
 hash operation for signing or verification as specified in 5.3.1.2.2 or
 5.3.1.3.
   - If payload does not contain the field omitted, the data input to the
 hash operation is the COER encoding of the ToBeSignedData.
   - If payload field in this ToBeSignedData instance contains the field
 omitted, the data input to the hash operation is the COER encoding of the
 ToBeSignedData, concatenated with the hash of the omitted payload. The hash
 of the omitted payload is calculated with the same hash algorithm that is
 used to calculate the hash of the data input for signing or verification.
 The data input to the hash operation is simply the COER enocding of the
 ToBeSignedData, concatenated with the hash of the omitted payload: there is
 no additional wrapping or length indication. As noted in 5.2.4.3.4, the
 means by which the signer and verifier establish the contents of the
 omitted payload are out of scope for this standard.

```asn1
ToBeSignedData ::= SEQUENCE { 
  payload    SignedDataPayload,
  headerInfo HeaderInfo
}
```

### <a name="SignedDataPayload"></a>SignedDataPayload

 This structure contains the data payload of a ToBeSignedData. This
 structure contains at least one of the optional elements, and may contain
 more than one. See 5.2.4.3.4 for more details.
 The security profile in Annex C allows an implementation of this standard
 to state which forms of Signed¬Data¬Payload are supported by that
 implementation, and also how the signer and verifier are intended to obtain
 the external data for hashing. The specification of an SDEE that uses
 external data is expected to be explicit and unambiguous about how this
 data is obtained and how it is formatted prior to processing by the hash
 function.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the Ieee1609Dot2Data.

Fields:
* data [**Ieee1609Dot2Data**](#Ieee1609Dot2Data)  OPTIONAL<br>
contains data that is explicitly transported within the
 structure.

* extDataHash [**HashedData**](#HashedData)  OPTIONAL<br>
contains the hash of data that is not explicitly
 transported within the structure, and which the creator of the structure
 wishes to cryptographically bind to the signature.

* omitted **NULL**  OPTIONAL<br>
indicates that there is external data to be included in the
 hash calculation for the signature.The mechanism for including the external
 data in the hash calculation is specified in 6.3.6.

```asn1
SignedDataPayload ::= SEQUENCE { 
  data        Ieee1609Dot2Data OPTIONAL,
  extDataHash HashedData OPTIONAL,
  ...,
  omitted     NULL OPTIONAL
} (WITH COMPONENTS {..., data PRESENT} |
   WITH COMPONENTS {..., extDataHash PRESENT} |
   WITH COMPONENTS {..., omitted PRESENT})
```

### <a name="HashedData"></a>HashedData

 This structure contains the hash of some data with a specified hash
 algorithm. See 5.3.3 for specification of the permitted hash algorithms.

 @note Critical information fields: If present, this is a critical
 information field as defined in 5.2.6. An implementation that does not
 recognize the indicated CHOICE for this type when verifying a signed SPDU
 shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,
 that is, it is invalid in the sense that its validity cannot be established.

Fields:
* sha256HashedData [**HashedId32**](Ieee1609Dot2BaseTypes.md#HashedId32) <br>
indicates data hashed with SHA-256.

* sha384HashedData [**HashedId48**](Ieee1609Dot2BaseTypes.md#HashedId48) <br>
indicates data hashed with SHA-384.

* sm3HashedData [**HashedId32**](Ieee1609Dot2BaseTypes.md#HashedId32) <br>
indicates data hashed with SM3.

```asn1
HashedData::= CHOICE { 
  sha256HashedData HashedId32,
  ...,
  sha384HashedData HashedId48,
  sm3HashedData    HashedId32
}
```

### <a name="HeaderInfo"></a>HeaderInfo

 This structure contains information that is used to establish
 validity by the criteria of 5.2.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the EncryptionKey. If encryptionKey is present, and indicates
 the choice public, and contains a BasePublicEncryptionKey that is an
 elliptic curve point (i.e., of type EccP256CurvePoint or
 EccP384CurvePoint), then the elliptic curve point is encoded in compressed
 form, i.e., such that the choice indicated within the Ecc*CurvePoint is
 compressed-y-0 or compressed-y-1.
 The canonicalization does not apply to any fields after the extension
 marker, including any fields in contributedExtensions.

Fields:
* psid [**Psid**](Ieee1609Dot2BaseTypes.md#Psid) <br>
indicates the application area with which the sender is
 claiming the payload is to be associated.

* generationTime [**Time64**](Ieee1609Dot2BaseTypes.md#Time64)  OPTIONAL<br>
indicates the time at which the structure was
 generated. See 5.2.5.2.2 and 5.2.5.2.3 for discussion of the use of this
 field.

* expiryTime [**Time64**](Ieee1609Dot2BaseTypes.md#Time64)  OPTIONAL<br>
if present, contains the time after which the data
 is no longer considered relevant. If both generationTime and
 expiryTime are present, the signed SPDU is invalid if generationTime is
 not strictly earlier than expiryTime.

* generationLocation [**ThreeDLocation**](Ieee1609Dot2BaseTypes.md#ThreeDLocation)  OPTIONAL<br>
if present, contains the location at which the
 signature was generated.

* p2pcdLearningRequest [**HashedId3**](Ieee1609Dot2BaseTypes.md#HashedId3)  OPTIONAL<br>
if present, is used by the SDS to request
 certificates for which it has seen identifiers and does not know the
 entire certificate. A specification of this peer-to-peer certificate
 distribution (P2PCD) mechanism is given in Clause 8. This field is used
 for the separate-certificate-pdu flavor of P2PCD and shall only be present
 if inlineP2pcdRequest is not present. The HashedId3 is calculated with the
 whole-certificate hash algorithm, determined as described in 6.4.3,
 applied to the COER-encoded certificate, canonicalized as defined in the
 definition of Certificate.

* missingCrlIdentifier [**MissingCrlIdentifier**](#MissingCrlIdentifier)  OPTIONAL<br>
if present, is used by the SDS to request
 CRLs which it knows to have been issued and have not received. This is
 provided for future use and the associated mechanism is not defined in
 this version of this standard.

* encryptionKey [**EncryptionKey**](Ieee1609Dot2BaseTypes.md#EncryptionKey)  OPTIONAL<br>
if present, is used to provide a key that is to
 be used to encrypt at least one response to this SPDU. The SDEE
 specification is expected to specify which response SPDUs are to be
 encrypted with this key. One possible use of this key to encrypt a
 response is specified in 6.3.35, 6.3.37, and 6.3.34. An encryptionKey
 field of type symmetric should only be used if the SignedData containing
 this field is securely encrypted by some means.

* inlineP2pcdRequest [**SequenceOfHashedId3**](Ieee1609Dot2BaseTypes.md#SequenceOfHashedId3)  OPTIONAL<br>
if present, is used by the SDS to request
 unknown certificates per the inline peer-to-peer certificate distribution
 mechanism is given in Clause 8. This field shall only be present if
 p2pcdLearningRequest is not present. The HashedId3 is calculated with the
 whole-certificate hash algorithm, determined as described in 6.4.3, applied
 to the COER-encoded certificate, canonicalized as defined in the definition
 of Certificate.

* requestedCertificate [**Certificate**](#Certificate)  OPTIONAL<br>
if present, is used by the SDS to provide
 certificates per the "inline" version of the peer-to-peer certificate
 distribution mechanism given in Clause 8.

* pduFunctionalType [**PduFunctionalType**](#PduFunctionalType)  OPTIONAL<br>
if present, is used to indicate that the SPDU is
 to be consumed by a process other than an application process as defined
 in ISO 21177 [B14a]. See 6.3.23b for more details.

* contributedExtensions [**ContributedExtensionBlocks**](#ContributedExtensionBlocks)  OPTIONAL<br>
if present, is used to contain additional
 extensions defined using the ContributedExtensionBlocks structure.

```asn1
HeaderInfo ::= SEQUENCE { 
  psid                  Psid,
  generationTime        Time64 OPTIONAL,
  expiryTime            Time64 OPTIONAL,
  generationLocation    ThreeDLocation OPTIONAL,
  p2pcdLearningRequest  HashedId3 OPTIONAL,
  missingCrlIdentifier  MissingCrlIdentifier OPTIONAL,
  encryptionKey         EncryptionKey OPTIONAL,
  ...,
  inlineP2pcdRequest    SequenceOfHashedId3 OPTIONAL,
  requestedCertificate  Certificate OPTIONAL,
  pduFunctionalType     PduFunctionalType OPTIONAL,
  contributedExtensions ContributedExtensionBlocks OPTIONAL
}
```

### <a name="MissingCrlIdentifier"></a>MissingCrlIdentifier

 This structure may be used to request a CRL that the SSME knows to
 have been issued and has not yet received. It is provided for future use
 and its use is not defined in this version of this standard.

Fields:
* cracaId [**HashedId3**](Ieee1609Dot2BaseTypes.md#HashedId3) <br>
is the HashedId3 of the CRACA, as defined in 5.1.3. The
 HashedId3 is calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3, applied to the COER-encoded certificate,
 canonicalized as defined in the definition of Certificate.

* crlSeries [**CrlSeries**](Ieee1609Dot2BaseTypes.md#CrlSeries) <br>
is the requested CRL Series value. See 5.1.3 for more
 information.

```asn1
MissingCrlIdentifier ::= SEQUENCE { 
  cracaId   HashedId3,
  crlSeries CrlSeries,
  ...
}
```

### <a name="PduFunctionalType"></a>PduFunctionalType

 This data structure identifies the functional entity that is
 intended to consume an SPDU, for the case where that functional entity is
 not an application process, and are instead security support services for an
 application process. Further details and the intended use of this field are
 defined in ISO 21177 [B20].
```asn1
PduFunctionalType ::= INTEGER (0..255)
```



```asn1
tlsHandshake             PduFunctionalType ::= 1
iso21177ExtendedAuth     PduFunctionalType ::= 2
iso21177SessionExtension PduFunctionalType ::= 3
```

### <a name="ContributedExtensionBlocks"></a>ContributedExtensionBlocks

 This type is used for clarity of definitions.



```asn1
ContributedExtensionBlocks ::= SEQUENCE (SIZE(1..MAX)) OF
  ContributedExtensionBlock
```

### <a name="ContributedExtensionBlock"></a>ContributedExtensionBlock

 This data structure defines the format of an extension block
 provided by an identified contributor by using the temnplate provided
 in the class IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION constraint
 to the objects in the set Ieee1609Dot2HeaderInfoContributedExtensions.

Values:
* contributorId [**IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION**](#IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION) .&id({
    Ieee1609Dot2HeaderInfoContributedExtensions
  })<br>
uniquely identifies the contributor.

* extns **SEQUENCE**  (SIZE(1..MAX)) OF<br>
contains a list of extensions from that contributor.
 Extensions are expected and not required to follow the format specified
 in 6.5.

* **Ieee1609Dot2HeaderInfoContributedExtensions** }{@.contributorId})<br>
```asn1
ContributedExtensionBlock ::= SEQUENCE {
  contributorId IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.&id({
    Ieee1609Dot2HeaderInfoContributedExtensions
  }),
  extns         SEQUENCE (SIZE(1..MAX)) OF
    IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION.&Extn({
    Ieee1609Dot2HeaderInfoContributedExtensions
  }{@.contributorId})
}
```

### <a name="IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION"></a>IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION

 This Information Object Class defines the class that provides a
 template for defining extension blocks.



```asn1
IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= CLASS {
  &id   HeaderInfoContributorId UNIQUE,
  &Extn
} WITH SYNTAX {&Extn IDENTIFIED BY &id}
```

### <a name="Ieee1609Dot2HeaderInfoContributedExtensions"></a>Ieee1609Dot2HeaderInfoContributedExtensions

 This structure is an ASN.1 Information Object Set listing the
 defined contributed extension types and the associated
 HeaderInfoContributorId values. In this version of this standard two
 extension types are defined: Ieee1609ContributedHeaderInfoExtension and
 EtsiOriginatingHeaderInfoExtension.



```asn1
Ieee1609Dot2HeaderInfoContributedExtensions
  IEEE1609DOT2-HEADERINFO-CONTRIBUTED-EXTENSION ::= {
  {Ieee1609ContributedHeaderInfoExtension IDENTIFIED BY 
        ieee1609HeaderInfoContributorId} |
  {EtsiOriginatingHeaderInfoExtension IDENTIFIED BY
    etsiHeaderInfoContributorId},
  ...
}
```

### <a name="HeaderInfoContributorId"></a>HeaderInfoContributorId

 This is an integer used to identify a HeaderInfo extension
 contributing organization. In this version of this standard two values are
 defined:
   - ieee1609OriginatingExtensionId indicating extensions originating with
 IEEE 1609.
   - etsiOriginatingExtensionId indicating extensions originating with
 ETSI TC ITS.



```asn1
HeaderInfoContributorId ::= INTEGER (0..255)
```



```asn1
ieee1609HeaderInfoContributorId HeaderInfoContributorId ::= 1
etsiHeaderInfoContributorId     HeaderInfoContributorId ::= 2
```

### <a name="SignerIdentifier"></a>SignerIdentifier

 This structure allows the recipient of data to determine which
 keying material to use to authenticate the data. It also indicates the
 verification type to be used to generate the hash for verification, as
 specified in 5.3.1.

 @note Critical information fields:
   - If present, this is a critical information field as defined in 5.2.6.
 An implementation that does not recognize the CHOICE value for this type
 when verifying a signed SPDU shall indicate that the signed SPDU is invalid.
   - If present, certificate is a critical information field as defined in
 5.2.6. An implementation that does not support the number of certificates
 in certificate when verifying a signed SPDU shall indicate that the signed
 SPDU is invalid. A compliant implementation shall support certificate
 fields containing at least one certificate.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to every Certificate in the certificate field.

Fields:
* digest [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
If the choice indicated is digest:
   - The structure contains the HashedId8 of the relevant certificate. The
 HashedId8 is calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3.
   - The verification type is certificate and the certificate data
 passed to the hash function as specified in 5.3.1 is the authorization
 certificate.

* certificate [**SequenceOfCertificate**](#SequenceOfCertificate) <br>
If the choice indicated is certificate:
   - The structure contains one or more Certificate structures, in order
 such that the first certificate is the authorization certificate and each
 subsequent certificate is the issuer of the one before it.
   - The verification type is certificate and the certificate data
 passed to the hash function as specified in 5.3.1 is the authorization
 certificate.

* self **NULL** <br>
If the choice indicated is self:
   - The structure does not contain any data beyond the indication that
 the choice value is self.
   - The verification type is self-signed.

```asn1
SignerIdentifier ::= CHOICE { 
  digest      HashedId8,
  certificate SequenceOfCertificate,
  self        NULL,
  ...
}
```

### <a name="Countersignature"></a>Countersignature

 This data structure is used to perform a countersignature over an
 already-signed SPDU. This is the profile of an Ieee1609Dot2Data containing
 a signedData. The tbsData within content is composed of a payload
 containing the hash (extDataHash) of the externally generated, pre-signed
 SPDU over which the countersignature is performed.



```asn1
Countersignature ::= Ieee1609Dot2Data (WITH COMPONENTS {...,
  content (WITH COMPONENTS {..., 
    signedData  (WITH COMPONENTS {..., 
      tbsData (WITH COMPONENTS {..., 
        payload (WITH COMPONENTS {..., 
          data ABSENT,
          extDataHash PRESENT
        }),
        headerInfo(WITH COMPONENTS {..., 
          generationTime PRESENT,
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

### <a name="EncryptedData"></a>EncryptedData

 This data structure encodes data that has been encrypted to one or
 more recipients using the recipients public or symmetric keys as
 specified in 5.3.4.

 @note Critical information fields:
   - If present, recipients is a critical information field as defined in
 5.2.6. An implementation that does not support the number of RecipientInfo
 in recipients when decrypted shall indicate that the encrypted SPDU could
 not be decrypted due to unsupported critical information fields. A
 compliant implementation shall support recipients fields containing at
 least eight entries.

 @note If the plaintext is raw data, i.e., it has not been output from a
 previous operation of the SDS, then it is trivial to encapsulate it in an
 Ieee1609Dot2Data of type unsecuredData as noted in 4.2.2.2.2. For example,
 '03 80 08 01 23 45 67 89 AB CD EF' is the C-OER encoding of '01 23 45 67
 89 AB CD EF' encapsulated in an Ieee1609Dot2Data of type unsecuredData.
 The first byte of the encoding 03 is the protocolVersion, the second byte
 80 indicates the choice unsecuredData, and the third byte 08 is the length
 of the raw data '01 23 45 67 89 AB CD EF'.

Fields:
* recipients [**SequenceOfRecipientInfo**](#SequenceOfRecipientInfo) <br>
contains one or more RecipientInfos. These entries may
 be more than one RecipientInfo, and more than one type of RecipientInfo,
 as long as all entries are indicating or containing the same data encryption
 key.

* ciphertext [**SymmetricCiphertext**](#SymmetricCiphertext) <br>
contains the encrypted data. This is the encryption of
 an encoded Ieee1609Dot2Data structure as specified in 5.3.4.2.

```asn1
EncryptedData ::= SEQUENCE {
  recipients SequenceOfRecipientInfo,
  ciphertext SymmetricCiphertext
}
```

### <a name="RecipientInfo"></a>RecipientInfo

 This data structure is used to transfer the data encryption key to
 an individual recipient of an EncryptedData. The option pskRecipInfo is
 selected if the EncryptedData was encrypted using the static encryption
 key approach specified in 5.3.4. The other options are selected if the
 EncryptedData was encrypted using the ephemeral encryption key approach
 specified in 5.3.4. The meanings of the choices are:

 See Annex C.7 for guidance on when it may be appropriate to use
 each of these approaches.

 @note If the encryption algorithm is SM2, there is no equivalent of the
 parameter P1 and so no input to the encryption process that uses the hash
 of the certificate.

 @note If the encryption algorithm is SM2, there is no equivalent of the
 parameter P1 and so no input to the encryption process that uses the hash
 of the Ieee1609Dot2Data.

 @note If the encryption algorithm is SM2, there is no equivalent of the
 parameter P1 and so no input to the encryption process that uses the hash
 of the empty string.

 @note The material input to encryption is the bytes of the encryption key
 with no headers, encapsulation, or length indication. Contrast this to
 encryption of data, where the data is encapsulated in an Ieee1609Dot2Data.

Fields:
* pskRecipInfo [**PreSharedKeyRecipientInfo**](#PreSharedKeyRecipientInfo) <br>
The data was encrypted directly using a pre-shared
 symmetric key.

* symmRecipInfo [**SymmRecipientInfo**](#SymmRecipientInfo) <br>
The data was encrypted with a data encryption key,
 and the data encryption key was encrypted using a symmetric key.

* certRecipInfo [**PKRecipientInfo**](#PKRecipientInfo) <br>
The data was encrypted with a data encryption key,
 the data encryption key was encrypted using a public key encryption scheme,
 where the public encryption key was obtained from a certificate. In this
 case, the parameter P1 to ECIES as defined in 5.3.5 is the hash of the
 certificate, calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3, applied to the COER-encoded certificate,
 canonicalized as defined in the definition of Certificate.

* signedDataRecipInfo [**PKRecipientInfo**](#PKRecipientInfo) <br>
The data was encrypted with a data encryption
 key, the data encryption key was encrypted using a public key encryption
 scheme, where the public encryption key was obtained as the public response
 encryption key from a SignedData. In this case, if ECIES is the encryption
 algorithm, then the parameter P1 to ECIES as defined in 5.3.5 is the
 SHA-256 hash of the Ieee1609Dot2Data of type signedData containing the
 response encryption key, canonicalized as defined in the definition of
 Ieee1609Dot2Data.

* rekRecipInfo [**PKRecipientInfo**](#PKRecipientInfo) <br>
The data was encrypted with a data encryption key,
 the data encryption key was encrypted using a public key encryption scheme,
 where the public encryption key was not obtained from a Signed-Data or a
 certificate. In this case, the SDEE specification is expected to specify
 how the public key is obtained, and if ECIES is the encryption algorithm,
 then the parameter P1 to ECIES as defined in 5.3.5 is the hash of the
 empty string.

```asn1
RecipientInfo ::= CHOICE {
  pskRecipInfo        PreSharedKeyRecipientInfo,
  symmRecipInfo       SymmRecipientInfo,
  certRecipInfo       PKRecipientInfo, 
  signedDataRecipInfo PKRecipientInfo, 
  rekRecipInfo        PKRecipientInfo 
}
```

### <a name="SequenceOfRecipientInfo"></a>SequenceOfRecipientInfo

 This type is used for clarity of definitions.



```asn1
SequenceOfRecipientInfo ::= SEQUENCE OF RecipientInfo
```

### <a name="PreSharedKeyRecipientInfo"></a>PreSharedKeyRecipientInfo

 This data structure is used to indicate a symmetric key that may
 be used directly to decrypt a SymmetricCiphertext. It consists of the
 low-order 8 bytes of the hash of the COER encoding of a
 SymmetricEncryptionKey structure containing the symmetric key in question.
 The HashedId8 is calculated with the hash algorithm determined as
 specified in 5.3.9.3. The symmetric key may be established by any
 appropriate means agreed by the two parties to the exchange.



```asn1
PreSharedKeyRecipientInfo ::= HashedId8
```

### <a name="SymmRecipientInfo"></a>SymmRecipientInfo

 This data structure contains the following fields:

Fields:
* recipientId [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
contains the hash of the symmetric key encryption key
 that may be used to decrypt the data encryption key. It consists of the
 low-order 8 bytes of the hash of the COER encoding of a
 SymmetricEncryptionKey structure containing the symmetric key in question.
 The HashedId8 is calculated with the hash algorithm determined as
 specified in 5.3.9.4. The symmetric key may be established by any
 appropriate means agreed by the two parties to the exchange.

* encKey [**SymmetricCiphertext**](#SymmetricCiphertext) <br>
contains the encrypted data encryption key within a
 SymmetricCiphertext, where the data encryption key is input to the data
 encryption key encryption process with no headers, encapsulation, or
 length indication.

```asn1
SymmRecipientInfo ::= SEQUENCE { 
  recipientId HashedId8, 
  encKey      SymmetricCiphertext
}
```

### <a name="PKRecipientInfo"></a>PKRecipientInfo

 This data structure contains the following fields:

Fields:
* recipientId [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
contains the hash of the container for the encryption
 public key as specified in the definition of RecipientInfo. Specifically,
 depending on the choice indicated by the containing RecipientInfo structure:
   - If the containing RecipientInfo structure indicates certRecipInfo,
 this field contains the HashedId8 of the certificate. The HashedId8 is
 calculated with the whole-certificate hash algorithm, determined as
 described in 6.4.3, applied to the COER-encoded certificate, canonicalized
 as defined in the definition of Certificate.
   - If the containing RecipientInfo structure indicates
 signedDataRecipInfo, this field contains the HashedId8 of the
 Ieee1609Dot2Data of type signedData that contained the encryption key,
 with that Ieee¬¬1609¬Dot2¬¬Data canonicalized per 6.3.4. The HashedId8 is
 calculated with the hash algorithm determined as specified in 5.3.9.5.
   - If the containing RecipientInfo structure indicates rekRecipInfo, this
 field contains the HashedId8 of the COER encoding of a PublicEncryptionKey
 structure containing the response encryption key. The HashedId8 is
 calculated with the hash algorithm determined as specified in 5.3.9.5.

* encKey [**EncryptedDataEncryptionKey**](#EncryptedDataEncryptionKey) <br>
contains the encrypted data encryption key, where the data
 encryption key is input to the data encryption key encryption process with
 no headers, encapsulation, or length indication.

```asn1
PKRecipientInfo ::= SEQUENCE { 
  recipientId HashedId8, 
  encKey      EncryptedDataEncryptionKey
}
```

### <a name="EncryptedDataEncryptionKey"></a>EncryptedDataEncryptionKey

 This data structure contains an encrypted data encryption key,
 where the data encryption key is input to the data encryption key
 encryption process with no headers, encapsulation, or length indication.

 Critical information fields: If present and applicable to
 the receiving SDEE, this is a critical information field as defined in
 5.2.6. If an implementation receives an encrypted SPDU and determines that
 one or more RecipientInfo fields are relevant to it, and if all of those
 RecipientInfos contain an EncryptedDataEncryptionKey such that the
 implementation does not recognize the indicated CHOICE, the implementation
 shall indicate that the encrypted SPDU is not decryptable.

Fields:
* eciesNistP256 [**EciesP256EncryptedKey**](Ieee1609Dot2BaseTypes.md#EciesP256EncryptedKey) <br>
* eciesBrainpoolP256r1 [**EciesP256EncryptedKey**](Ieee1609Dot2BaseTypes.md#EciesP256EncryptedKey) <br>
* ecencSm2256 [**EcencP256EncryptedKey**](Ieee1609Dot2BaseTypes.md#EcencP256EncryptedKey) <br>
```asn1
EncryptedDataEncryptionKey ::= CHOICE { 
  eciesNistP256        EciesP256EncryptedKey,
  eciesBrainpoolP256r1 EciesP256EncryptedKey,
  ...,
  ecencSm2256          EcencP256EncryptedKey
}
```

### <a name="SymmetricCiphertext"></a>SymmetricCiphertext

 This data structure encapsulates a ciphertext generated with an
 approved symmetric algorithm.

 @note Critical information fields: If present, this is a critical
 information field as defined in 5.2.6. An implementation that does not
 recognize the indicated CHOICE value for this type in an encrypted SPDU
 shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,
 that is, it is invalid in the sense that its validity cannot be established.

Fields:
* aes128ccm [**One28BitCcmCiphertext**](#One28BitCcmCiphertext) <br>
* sm4Ccm [**One28BitCcmCiphertext**](#One28BitCcmCiphertext) <br>
```asn1
SymmetricCiphertext ::= CHOICE {
  aes128ccm One28BitCcmCiphertext,
  ...,
  sm4Ccm    One28BitCcmCiphertext
}
```

### <a name="One28BitCcmCiphertext"></a>One28BitCcmCiphertext

 This data structure encapsulates an encrypted ciphertext for any
 symmetric algorithm with 128-bit blocks in CCM mode. The ciphertext is
 16 bytes longer than the corresponding plaintext due to the inclusion of
 the message authentication code (MAC). The plaintext resulting from a
 correct decryption of the ciphertext is either a COER-encoded
 Ieee1609Dot2Data structure (see 6.3.41), or a 16-byte symmetric key
 (see 6.3.44).

 The ciphertext is 16 bytes longer than the corresponding plaintext.

 The plaintext resulting from a correct decryption of the
 ciphertext is a COER-encoded Ieee1609Dot2Data structure.

 @note In the name of this structure, "One28" indicates that the
 symmetric cipher block size is 128 bits. It happens to also be the case
 that the keys used for both AES-128-CCM and SM4-CCM are also 128 bits long.
 This is, however, not what One28 refers to. Since the cipher is used in
 counter mode, i.e., as a stream cipher, the fact that that block size is 128
 bits affects only the size of the MAC and does not affect the size of the
 raw ciphertext.

Fields:
* nonce **OCTET STRING**  (SIZE (12))<br>
contains the nonce N as specified in 5.3.8.

* ccmCiphertext [**Opaque**](Ieee1609Dot2BaseTypes.md#Opaque) <br>
contains the ciphertext C as specified in 5.3.8.

```asn1
One28BitCcmCiphertext ::= SEQUENCE {
  nonce         OCTET STRING (SIZE (12)),
  ccmCiphertext Opaque 
}
```

### <a name="Aes128CcmCiphertext"></a>Aes128CcmCiphertext

 This type is defined only for backwards compatibility.



```asn1
Aes128CcmCiphertext ::= One28BitCcmCiphertext
```

### <a name="TestCertificate"></a>TestCertificate

 This structure is a profile of the structure CertificateBase which
 specifies the valid combinations of fields to transmit implicit and
 explicit certificates.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the CertificateBase.



```asn1
TestCertificate ::= Certificate
```

### <a name="SequenceOfCertificate"></a>SequenceOfCertificate

 This type is used for clarity of definitions.



```asn1
SequenceOfCertificate ::= SEQUENCE OF Certificate
```

### <a name="CertificateBase"></a>CertificateBase

 The fields in this structure have the following meaning:

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the ToBeSignedCertificate and to the Signature.

 @note Whole-certificate hash: If the entirety of a certificate is hashed
 to calculate a HashedId3, HashedId8, or HashedId10, the algorithm used for
 this purpose is known as the whole-certificate hash. The method used to
 determine the whole-certificate hash algorithm is specified in 5.3.9.2.

Fields:
* version [**Uint8**](Ieee1609Dot2BaseTypes.md#Uint8) (3)<br>
contains the version of the certificate format. In this
 version of the data structures, this field is set to 3.

* type [**CertificateType**](#CertificateType) <br>
states whether the certificate is implicit or explicit. This
 field is set to explicit for explicit certificates and to implicit for
 implicit certificates. See ExplicitCertificate and ImplicitCertificate for
 more details.

* issuer [**IssuerIdentifier**](#IssuerIdentifier) <br>
identifies the issuer of the certificate.

* toBeSigned [**ToBeSignedCertificate**](#ToBeSignedCertificate) <br>
is the certificate contents. This field is an input to
 the hash when generating or verifying signatures for an explicit
 certificate, or generating or verifying the public key from the
 reconstruction value for an implicit certificate. The details of how this
 field are encoded are given in the description of the
 ToBeSignedCertificate type.

* signature [**Signature**](Ieee1609Dot2BaseTypes.md#Signature)  OPTIONAL<br>
is included in an ExplicitCertificate. It is the
 signature, calculated by the signer identified in the issuer field, over
 the hash of toBeSigned. The hash is calculated as specified in 5.3.1, where:
   - Data input is the encoding of toBeSigned following the COER.
   - Signer identifier input depends on the verification type, which in
 turn depends on the choice indicated by issuer. If the choice indicated by
 issuer is self, the verification type is self-signed and the signer
 identifier input is the empty string. If the choice indicated by issuer is
 not self, the verification type is certificate and the signer identifier
 input is the canonicalized COER encoding of the certificate indicated by
 issuer. The canonicalization is carried out as specified in the
 Canonicalization section of this subclause.

```asn1
CertificateBase ::= SEQUENCE {
  version    Uint8(3),
  type       CertificateType,
  issuer     IssuerIdentifier,
  toBeSigned ToBeSignedCertificate,
  signature  Signature OPTIONAL
}
```

### <a name="CertificateType"></a>CertificateType

 This enumerated type indicates whether a certificate is explicit or
 implicit.

 @note Critical information fields: If present, this is a critical
 information field as defined in 5.2.5. An implementation that does not
 recognize the indicated CHOICE for this type when verifying a signed SPDU
 shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,
 that is, it is invalid in the sense that its validity cannot be
 established.



```asn1
CertificateType ::= ENUMERATED {
  explicit,
  implicit,
  ...
}
```

### <a name="ImplicitCertificate"></a>ImplicitCertificate

 This is a profile of the CertificateBase structure providing all
 the fields necessary for an implicit certificate, and no others.



```asn1
ImplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
  type(implicit),
  toBeSigned(WITH COMPONENTS {...,
    verifyKeyIndicator(WITH COMPONENTS {reconstructionValue})
  }),
  signature ABSENT
})
```

### <a name="ExplicitCertificate"></a>ExplicitCertificate

 This is a profile of the CertificateBase structure providing all
 the fields necessary for an explicit certificate, and no others.



```asn1
ExplicitCertificate ::= CertificateBase (WITH COMPONENTS {...,
  type(explicit),
  toBeSigned (WITH COMPONENTS {...,
    verifyKeyIndicator(WITH COMPONENTS {verificationKey})
  }),
  signature PRESENT
})
```

### <a name="IssuerIdentifier"></a>IssuerIdentifier

 This structure allows the recipient of a certificate to determine
 which keying material to use to authenticate the certificate.

 If the choice indicated is sha256AndDigest, sha384AndDigest, or
 sm3AndDigest:
   - The structure contains the HashedId8 of the issuing certificate. The
 HashedId8 is calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3, applied to the COER-encoded certificate,
 canonicalized as defined in the definition of Certificate.
   - The hash algorithm to be used to generate the hash of the certificate
 for verification is SHA-256 (in the case of sha256AndDigest), SM3 (in the
 case of sm3AndDigest) or SHA-384 (in the case of sha384AndDigest).
   - The certificate is to be verified with the public key of the
 indicated issuing certificate.

 If the choice indicated is self:
   - The structure indicates what hash algorithm is to be used to generate
 the hash of the certificate for verification.
   - The certificate is to be verified with the public key indicated by
 the verifyKeyIndicator field in theToBeSignedCertificate.

 @note Critical information fields: If present, this is a critical
 information field as defined in 5.2.5. An implementation that does not
 recognize the indicated CHOICE for this type when verifying a signed SPDU
 shall indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2,
 that is, it is invalid in the sense that its validity cannot be
 established.

Fields:
* sha256AndDigest [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
* self [**HashAlgorithm**](Ieee1609Dot2BaseTypes.md#HashAlgorithm) <br>
* sha384AndDigest [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
* sm3AndDigest [**HashedId8**](Ieee1609Dot2BaseTypes.md#HashedId8) <br>
```asn1
IssuerIdentifier ::= CHOICE { 
  sha256AndDigest HashedId8,
  self            HashAlgorithm,
  ...,
  sha384AndDigest HashedId8,
  sm3AndDigest    HashedId8
}
```

### <a name="ToBeSignedCertificate"></a>ToBeSignedCertificate

 The fields in the ToBeSignedCertificate structure have the
 following meaning:

 For both implicit and explicit certificates, when the certificate
 is hashed to create or recover the public key (in the case of an implicit
 certificate) or to generate or verify the signature (in the case of an
 explicit certificate), the hash is Hash (Data input) || Hash (
 Signer identifier input), where:
   - Data input is the COER encoding of toBeSigned, canonicalized
 as described above.
   - Signer identifier input depends on the verification type,
 which in turn depends on the choice indicated by issuer. If the choice
 indicated by issuer is self, the verification type is self-signed and the
 signer identifier input is the empty string. If the choice indicated by
 issuer is not self, the verification type is certificate and the signer
 identifier input is the COER encoding of the canonicalization per 6.4.3 of
 the certificate indicated by issuer.

 In other words, for implicit certificates, the value H (CertU) in SEC 4,
 section 3, is for purposes of this standard taken to be H [H
 (canonicalized ToBeSignedCertificate from the subordinate certificate) ||
 H (entirety of issuer Certificate)]. See 5.3.2 for further discussion,
 including material differences between this standard and SEC 4 regarding
 how the hash function output is converted from a bit string to an integer.

 @note usesCubk is only relevant for CA certificates, and the only
 functionality defined associated with this field is associated with
 consistency checks on received certificate responses. No functionality
 associated with communications between peer SDEEs is defined associated
 with this field.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the PublicEncryptionKey and to the VerificationKeyIndicator.

 If the PublicEncryptionKey contains a BasePublicEncryptionKey that is an
 elliptic curve point (i.e., of type EccP256CurvePoint or EccP384CurvePoint),
 then the elliptic curve point is encoded in compressed form, i.e., such
 that the choice indicated within the Ecc*CurvePoint is compressed-y-0 or
 compressed-y-1.

 @note Critical information fields:
   - If present, appPermissions is a critical information field as defined
 in 5.2.6. If an implementation of verification does not support the number
 of PsidSsp in the appPermissions field of a certificate that signed a
 signed SPDU, that implementation shall indicate that the signed SPDU is
 invalid in the sense of 4.2.2.3.2, that is, it is invalid in the sense
 that its validity cannot be established.. A conformant implementation
 shall support appPermissions fields containing at least eight entries.
 It may be the case that an implementation of verification does not support
 the number of entries in  the appPermissions field and the appPermissions
 field is not relevant to the verification: this will occur, for example,
 if the certificate in question is a CA certificate and so the
 certIssuePermissions field is relevant to the verification and the
 appPermissions field is not. In this case, whether the implementation
 indicates that the signed SPDU is valid (because it could validate all
 relevant fields) or invalid (because it could not parse the entire
 certificate) is implementation-specific.
   - If present, certIssuePermissions is a critical information field as
 defined in 5.2.6. If an implementation of verification does not support
 the number of PsidGroupPermissions in the certIssuePermissions field of a
 CA certificate in the chain of a signed SPDU, the implementation shall
 indicate that the signed SPDU is invalid in the sense of 4.2.2.3.2, that
 is, it is invalid in the sense that its validity cannot be established.
 A conformant implementation shall support certIssuePermissions fields
 containing at least eight entries.
 It may be the case that an implementation of verification does not support
 the number of entries in  the certIssuePermissions field and the
 certIssuePermissions field is not relevant to the verification: this will
 occur, for example, if the certificate in question is the signing
 certificate for the SPDU and so the appPermissions field is relevant to
 the verification and the certIssuePermissions field is not. In this case,
 whether the implementation indicates that the signed SPDU is valid
 (because it could validate all relevant fields) or invalid (because it
 could not parse the entire certificate) is implementation-specific.
   - If present, certRequestPermissions is a critical information field as
 defined in 5.2.6. If an implementaiton of verification of a certificate
 request does not support the number of PsidGroupPermissions in
 certRequestPermissions, the implementation shall indicate that the signed
 SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the
 sense that its validity cannot be established. A conformant implementation
 shall support certRequestPermissions fields containing at least eight
 entries.
 It may be the case that an implementation of verification does not support
 the number of entries in  the certRequestPermissions field and the
 certRequestPermissions field is not relevant to the verification: this will
 occur, for example, if the certificate in question is the signing
 certificate for the SPDU and so the appPermissions field is relevant to
 the verification and the certRequestPermissions field is not. In this
 case, whether the implementation indicates that the signed SPDU is valid
 (because it could validate all relevant fields) or invalid (because it
 could not parse the entire certificate) is implementation-specific.

Fields:
* id [**CertificateId**](#CertificateId) <br>
contains information that is used to identify the certificate
 holder if necessary.

* cracaId [**HashedId3**](Ieee1609Dot2BaseTypes.md#HashedId3) <br>
identifies the Certificate Revocation Authorization CA
 (CRACA) responsible for certificate revocation lists (CRLs) on which this
 certificate might appear. Use of the cracaId is specified in 5.1.3. The
 HashedId3 is calculated with the whole-certificate hash algorithm,
 determined as described in 6.4.3, applied to the COER-encoded certificate,
 canonicalized as defined in the definition of Certificate.

* crlSeries [**CrlSeries**](Ieee1609Dot2BaseTypes.md#CrlSeries) <br>
represents the CRL series relevant to a particular
 Certificate Revocation Authorization CA (CRACA) on which the certificate
 might appear. Use of this field is specified in 5.1.3.

* validityPeriod [**ValidityPeriod**](Ieee1609Dot2BaseTypes.md#ValidityPeriod) <br>
contains the validity period of the certificate.

* region [**GeographicRegion**](Ieee1609Dot2BaseTypes.md#GeographicRegion)  OPTIONAL<br>
if present, indicates the validity region of the
 certificate. If it is omitted the validity region is indicated as follows:
   - If enclosing certificate is self-signed, i.e., the choice indicated
 by the issuer field in the enclosing certificate structure is self, the
 certificate is valid worldwide.
   - Otherwise, the certificate has the same validity region as the
 certificate that issued it.

* assuranceLevel [**SubjectAssurance**](Ieee1609Dot2BaseTypes.md#SubjectAssurance)  OPTIONAL<br>
indicates the assurance level of the certificate
 holder.

* appPermissions [**SequenceOfPsidSsp**](Ieee1609Dot2BaseTypes.md#SequenceOfPsidSsp)  OPTIONAL<br>
indicates the permissions that the certificate
 holder has to sign application data with this certificate. A valid
 instance of appPermissions contains any particular Psid value in at most
 one entry.

* certIssuePermissions [**SequenceOfPsidGroupPermissions**](#SequenceOfPsidGroupPermissions)  OPTIONAL<br>
indicates the permissions that the certificate
 holder has to sign certificates with this certificate. A valid instance of
 this array contains no more than one entry whose psidSspRange field
 indicates all. If the array has multiple entries and one entry has its
 psidSspRange field indicate all, then the entry indicating all specifies
 the permissions for all PSIDs other than the ones explicitly specified in
 the other entries. See the description of PsidGroupPermissions for further
 discussion.

* certRequestPermissions [**SequenceOfPsidGroupPermissions**](#SequenceOfPsidGroupPermissions)  OPTIONAL<br>
indicates the permissions that the
 certificate holder can request in its certificate. A valid instance of this
 array contains no more than one entry whose psidSspRange field indicates
 all. If the array has multiple entries and one entry has its psidSspRange
 field indicate all, then the entry indicating all specifies the permissions
 for all PSIDs other than the ones explicitly specified in the other entries.
 See the description of PsidGroupPermissions for further discussion.

* canRequestRollover **NULL**  OPTIONAL<br>
indicates that the certificate may be used to
 sign a request for another certificate with the same permissions. This
 field is provided for future use and its use is not defined in this
 version of this standard.

* encryptionKey [**PublicEncryptionKey**](Ieee1609Dot2BaseTypes.md#PublicEncryptionKey)  OPTIONAL<br>
contains a public key for encryption for which the
 certificate holder holds the corresponding private key.

* verifyKeyIndicator [**VerificationKeyIndicator**](#VerificationKeyIndicator) <br>
contains material that may be used to recover
 the public key that may be used to verify data signed by this certificate.

* flags **BIT STRING**  {usesCubk (0)} (SIZE (8)) OPTIONAL<br>
indicates additional yes/no properties of the certificate
 holder. The only bit with defined semantics in this string in this version
 of this standard is usesCubk. If set, the usesCubk bit indicates that the
 certificate holder supports the compact unified butterfly key response.
 Further material about the compact unified butterfly key response can be
 found in IEEE Std 1609.2.1.

* appExtensions [**SequenceOfAppExtensions**](#SequenceOfAppExtensions) <br>
indicates additional permissions that may be applied
 to application activities that the certificate holder is carrying out.

* certIssueExtensions [**SequenceOfCertIssueExtensions**](#SequenceOfCertIssueExtensions) <br>
indicates additional permissions to issue
 certificates containing endEntityExtensions.

* certRequestExtension [**SequenceOfCertRequestExtensions**](#SequenceOfCertRequestExtensions) <br>
```asn1
ToBeSignedCertificate ::= SEQUENCE { 
  id                     CertificateId,
  cracaId                HashedId3,
  crlSeries              CrlSeries,
  validityPeriod         ValidityPeriod,
  region                 GeographicRegion OPTIONAL,
  assuranceLevel         SubjectAssurance OPTIONAL,
  appPermissions         SequenceOfPsidSsp OPTIONAL,
  certIssuePermissions   SequenceOfPsidGroupPermissions OPTIONAL,
  certRequestPermissions SequenceOfPsidGroupPermissions OPTIONAL, 
  canRequestRollover     NULL OPTIONAL,
  encryptionKey          PublicEncryptionKey OPTIONAL,
  verifyKeyIndicator     VerificationKeyIndicator,
  ...,
  flags                  BIT STRING {usesCubk (0)} (SIZE (8)) OPTIONAL,
  appExtensions          SequenceOfAppExtensions,
  certIssueExtensions    SequenceOfCertIssueExtensions,
  certRequestExtension   SequenceOfCertRequestExtensions
}
(WITH COMPONENTS { ..., appPermissions PRESENT} |
 WITH COMPONENTS { ..., certIssuePermissions PRESENT} |
 WITH COMPONENTS { ..., certRequestPermissions PRESENT})
```

### <a name="CertificateId"></a>CertificateId

 This structure contains information that is used to identify the
 certificate holder if necessary.

 @note Critical information fields:
   - If present, this is a critical information field as defined in 5.2.6.
 An implementation that does not recognize the choice indicated in this
 field shall reject a signed SPDU as invalid.

Fields:
* linkageData [**LinkageData**](#LinkageData) <br>
is used to identify the certificate for revocation
 purposes in the case of certificates that appear on linked certificate
 CRLs. See 5.1.3 and 7.3 for further discussion.

* name [**Hostname**](Ieee1609Dot2BaseTypes.md#Hostname) <br>
is used to identify the certificate holder in the case of
 non-anonymous certificates. The contents of this field are a matter of
 policy and are expected to be human-readable.

* binaryId **OCTET STRING** (SIZE(1..64))<br>
supports identifiers that are not human-readable.

* none **NULL** <br>
indicates that the certificate does not include an identifier.

```asn1
CertificateId ::= CHOICE {
  linkageData LinkageData,
  name        Hostname,
  binaryId    OCTET STRING(SIZE(1..64)),
  none        NULL,
  ...
}
```

### <a name="LinkageData"></a>LinkageData

 This structure contains information that is matched against
 information obtained from a linkage ID-based CRL to determine whether the
 containing certificate has been revoked. See 5.1.3.4 and 7.3 for details
 of use.

Fields:
* iCert [**IValue**](Ieee1609Dot2BaseTypes.md#IValue) <br>
* linkage-value [**LinkageValue**](Ieee1609Dot2BaseTypes.md#LinkageValue) <br>
* group-linkage-value [**GroupLinkageValue**](Ieee1609Dot2BaseTypes.md#GroupLinkageValue)  OPTIONAL<br>
```asn1
LinkageData ::= SEQUENCE {
  iCert               IValue,
  linkage-value       LinkageValue, 
  group-linkage-value GroupLinkageValue OPTIONAL
}
```

### <a name="PsidGroupPermissions"></a>PsidGroupPermissions

 This type indicates which type of permissions may appear in
 end-entity certificates the chain of whose permissions passes through the
 PsidGroupPermissions field containing this value. If app is indicated, the
 end-entity certificate may contain an appPermissions field. If enroll is
 indicated, the end-entity certificate may contain a certRequestPermissions
 field.

 This structure states the permissions that a certificate holder has
 with respect to issuing and requesting certificates for a particular set
 of PSIDs. For examples, see D.5.3 and D.5.4.

Fields:
* subjectPermissions [**SubjectPermissions**](#SubjectPermissions) <br>
indicates PSIDs and SSP Ranges covered by this
 field.

* minChainLength **INTEGER**  DEFAULT 1<br>
and chainLengthRange indicate how long the
 certificate chain from this certificate to the end-entity certificate is
 permitted to be. As specified in 5.1.2.1, the length of the certificate
 chain is the number of certificates "below" this certificate in the chain,
 down to and including the end-entity certificate. The length is permitted
 to be (a) greater than or equal to minChainLength certificates and (b)
 less than or equal to minChainLength + chainLengthRange certificates. A
 value of 0 for minChainLength is not permitted when this type appears in
 the certIssuePermissions field of a ToBeSignedCertificate; a certificate
 that has a value of 0 for this field is invalid. The value -1 for
 chainLengthRange is a special case: if the value of chainLengthRange is -1
 it indicates that the certificate chain may be any length equal to or
 greater than minChainLength. See the examples below for further discussion.

* chainLengthRange **INTEGER**  DEFAULT 0<br>
* eeType [**EndEntityType**](#EndEntityType)  DEFAULT {app}<br>
takes one or more of the values app and enroll and indicates
 the type of certificates or requests that this instance of
 PsidGroupPermissions in the certificate is entitled to authorize.
 Different instances of PsidGroupPermissions within a ToBeSignedCertificate
 may have different values for eeType.
   - If this field indicates app, the chain is allowed to end in an
 authorization certificate, i.e., a certficate in which these permissions
 appear in an appPermissions field (in other words, if the field does not
 indicate app and the chain ends in an authorization certificate, the
 chain shall be considered invalid).
   - If this field indicates enroll, the chain is allowed to end in an
 enrollment certificate, i.e., a certificate in which these permissions
 appear in a certReqPermissions permissions field (in other words, if the
 field does not indicate enroll and the chain ends in an enrollment
 certificate, the chain shall be considered invalid).

```asn1
PsidGroupPermissions ::= SEQUENCE {
  subjectPermissions SubjectPermissions,
  minChainLength     INTEGER DEFAULT 1, 
  chainLengthRange   INTEGER DEFAULT 0, 
  eeType             EndEntityType DEFAULT {app}
}
```

### <a name="SequenceOfPsidGroupPermissions"></a>SequenceOfPsidGroupPermissions

 This type is used for clarity of definitions.



```asn1
SequenceOfPsidGroupPermissions ::= SEQUENCE OF PsidGroupPermissions
```

### <a name="SubjectPermissions"></a>SubjectPermissions

 This indicates the PSIDs and associated SSPs for which certificate
 issuance or request permissions are granted by a PsidGroupPermissions
 structure. If this takes the value explicit, the enclosing
 PsidGroupPermissions structure grants certificate issuance or request
 permissions for the indicated PSIDs and SSP Ranges. If this takes the
 value all, the enclosing PsidGroupPermissions structure grants certificate
 issuance or request permissions for all PSIDs not indicated by other
 PsidGroupPermissions in the same certIssuePermissions or
 certRequestPermissions field.

 @note Critical information fields:
   - If present, this is a critical information field as defined in 5.2.6.
 An implementation that does not recognize the indicated CHOICE when
 verifying a signed SPDU shall indicate that the signed SPDU is
 invalidin the sense of 4.2.2.3.2, that is, it is invalid in the sense that
 its validity cannot be established.
   - If present, explicit is a critical information field as defined in
 5.2.6. An implementation that does not support the number of PsidSspRange
 in explicit when verifying a signed SPDU shall indicate that the signed
 SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the
 sense that its validity cannot be established. A conformant implementation
 shall support explicit fields containing at least eight entries.

Fields:
* explicit [**SequenceOfPsidSspRange**](Ieee1609Dot2BaseTypes.md#SequenceOfPsidSspRange) <br>
* all **NULL** <br>
```asn1
SubjectPermissions ::= CHOICE {
  explicit SequenceOfPsidSspRange,
  all      NULL,
  ...
}
```

### <a name="VerificationKeyIndicator"></a>VerificationKeyIndicator

 The contents of this field depend on whether the certificate is an
 implicit or an explicit certificate.

 @note Critical information fields: If present, this is a critical
 information field as defined in 5.2.5. An implementation that does not
 recognize the indicated CHOICE for this type when verifying a signed SPDU
 shall indicate that the signed SPDU is invalid indicate that the signed
 SPDU is invalid in the sense of 4.2.2.3.2, that is, it is invalid in the
 sense that its validity cannot be established.

 @note Canonicalization: This data structure is subject to canonicalization
 for the relevant operations specified in 6.1.2. The canonicalization
 applies to the PublicVerificationKey and to the EccP256CurvePoint. The
 EccP256CurvePoint is encoded in compressed form, i.e., such that the
 choice indicated within the EccP256CurvePoint is compressed-y-0 or
 compressed-y-1.

Fields:
* verificationKey [**PublicVerificationKey**](Ieee1609Dot2BaseTypes.md#PublicVerificationKey) <br>
is included in explicit certificates. It contains
 the public key to be used to verify signatures generated by the holder of
 the Certificate.

* reconstructionValue [**EccP256CurvePoint**](Ieee1609Dot2BaseTypes.md#EccP256CurvePoint) <br>
is included in implicit certificates. It
 contains the reconstruction value, which is used to recover the public key
 as specified in SEC 4 and 5.3.2.

```asn1
VerificationKeyIndicator ::= CHOICE {
  verificationKey     PublicVerificationKey,
  reconstructionValue EccP256CurvePoint,
  ...
}
```

### <a name="Ieee1609HeaderInfoExtensionId"></a>Ieee1609HeaderInfoExtensionId

 This structure uses the parameterized type Extension to define an
 Ieee1609ContributedHeaderInfoExtension as an open Extension Content field
 identified by an extension identifier. The extension identifier value is
 unique to extensions defined by ETSI and need not be unique among all
 extension identifier values defined by all contributing organizations.

 This is an integer used to identify an
 Ieee1609ContributedHeaderInfoExtension.



```asn1
Ieee1609HeaderInfoExtensionId ::= ExtId
```



```asn1
p2pcd8ByteLearningRequestId Ieee1609HeaderInfoExtensionId ::= 1
```

### <a name="Ieee1609HeaderInfoExtensions"></a>Ieee1609HeaderInfoExtensions

 This is the ASN.1 Information Object Class that associates IEEE
 1609 HeaderInfo contributed extensions with the appropriate
 Ieee1609HeaderInfoExtensionId value.



```asn1
Ieee1609HeaderInfoExtensions EXT-TYPE ::= {
  {HashedId8 IDENTIFIED BY p2pcd8ByteLearningRequestId},
  ...
}
```

### <a name="SequenceOfAppExtensions"></a>SequenceOfAppExtensions

 This structure contains any AppExtensions that apply to the
 certificate holder. As specified in 5.2.4.2.3, each individual
 AppExtension type is associated with consistency conditions, specific to
 that extension, that govern its consistency with SPDUs signed by the
 certificate holder and with the CertIssueExtensions in the CA certificates
 in that certificate holders chain. Those consistency conditions are
 specified for each individual AppExtension below.



```asn1
SequenceOfAppExtensions ::= SEQUENCE (SIZE(1..MAX)) OF AppExtension
```

### <a name="AppExtension"></a>AppExtension

 This structure contains an individual AppExtension. AppExtensions
 specified in this standard are drawn from the ASN.1 Information Object Set
 SetCertExtensions. This set, and its use in the AppExtension type, is
 structured so that each AppExtension is associated with a
 CertIssueExtension and a CertRequestExtension and all are identified by
 the same id value. In this structure:

Fields:
* id [**CERT-EXT-TYPE**](Ieee1609Dot2BaseTypes.md#CERT-EXT-TYPE) .&id({SetCertExtensions})<br>
identifies the extension type.

* content [**CERT-EXT-TYPE**](Ieee1609Dot2BaseTypes.md#CERT-EXT-TYPE) .&App({SetCertExtensions}{@.id})<br>
provides the content of the extension.

```asn1
AppExtension ::= SEQUENCE {
  id      CERT-EXT-TYPE.&id({SetCertExtensions}),
  content CERT-EXT-TYPE.&App({SetCertExtensions}{@.id})
}
```

### <a name="SequenceOfCertIssueExtensions"></a>SequenceOfCertIssueExtensions

 This field contains any CertIssueExtensions that apply to the
 certificate holder. As specified in 5.2.4.2.3, each individual
 CertIssueExtension type is associated with consistency conditions,
 specific to that extension, that govern its consistency with
 AppExtensions in certificates issued by the certificate holder and with
 the CertIssueExtensions in the CA certificates in that certificate
 holders chain. Those consistency conditions are specified for each
 individual CertIssueExtension below.



```asn1
SequenceOfCertIssueExtensions ::= 
  SEQUENCE (SIZE(1..MAX)) OF CertIssueExtension
```

### <a name="CertIssueExtension"></a>CertIssueExtension

 This field contains an individual CertIssueExtension.
 CertIssueExtensions specified in this standard are drawn from the ASN.1
 Information Object Set SetCertExtensions. This set, and its use in the
 CertIssueExtension type, is structured so that each CertIssueExtension
 is associated with a AppExtension and a CertRequestExtension and all are
 identified by the same id value. In this structure:

Fields:
* id [**CERT-EXT-TYPE**](Ieee1609Dot2BaseTypes.md#CERT-EXT-TYPE) .&id({SetCertExtensions})<br>
identifies the extension type.

* permissions [**CHOICE**](#CHOICE)  {
    specific  CERT-EXT-TYPE.&Issue({SetCertExtensions}{@.id})<br>
indicates the permissions. Within this field.
   - all indicates that the certificate is entitled to issue all values of
 the extension.
   - specific is used to specify which values of the extension may be
 issued in the case where all does not apply.

* all **NULL** <br>
```asn1
CertIssueExtension ::= SEQUENCE {
  id          CERT-EXT-TYPE.&id({SetCertExtensions}),
  permissions CHOICE {
    specific  CERT-EXT-TYPE.&Issue({SetCertExtensions}{@.id}),
    all       NULL
  }
}
```

### <a name="SequenceOfCertRequestExtensions"></a>SequenceOfCertRequestExtensions

 This field contains any CertRequestExtensions that apply to the
 certificate holder. As specified in 5.2.4.2.3, each individual
 CertRequestExtension type is associated with consistency conditions,
 specific to that extension, that govern its consistency with
 AppExtensions in certificates issued by the certificate holder and with
 the CertRequestExtensions in the CA certificates in that certificate
 holders chain. Those consistency conditions are specified for each
 individual CertRequestExtension below.



```asn1
SequenceOfCertRequestExtensions ::= SEQUENCE (SIZE(1..MAX)) OF CertRequestExtension
```

### <a name="CertRequestExtension"></a>CertRequestExtension

 This field contains an individual CertRequestExtension.
 CertRequestExtensions specified in this standard are drawn from the
 ASN.1 Information Object Set SetCertExtensions. This set, and its use in
 the CertRequestExtension type, is structured so that each
 CertRequestExtension is associated with a AppExtension and a
 CertRequestExtension and all are identified by the same id value. In this
 structure:

Fields:
* id [**CERT-EXT-TYPE**](Ieee1609Dot2BaseTypes.md#CERT-EXT-TYPE) .&id({SetCertExtensions})<br>
identifies the extension type.

* permissions [**CHOICE**](#CHOICE)  {
    content   CERT-EXT-TYPE.&Req({SetCertExtensions}{@.id})<br>
indicates the permissions. Within this field.
   - all indicates that the certificate is entitled to issue all values of
 the extension.
   - specific is used to specify which values of the extension may be
 issued in the case where all does not apply.

* all **NULL** <br>
```asn1
CertRequestExtension ::= SEQUENCE {
  id      CERT-EXT-TYPE.&id({SetCertExtensions}),
  permissions CHOICE {
    content   CERT-EXT-TYPE.&Req({SetCertExtensions}{@.id}),
    all       NULL
  }
}
```

### <a name="OperatingOrganizationId"></a>OperatingOrganizationId

 This type is the AppExtension used to identify an operating
 organization. The associated CertIssueExtension and CertRequestExtension
 are both of type OperatingOrganizationId.
 To determine consistency between this type and an SPDU, the SDEE
 specification for that SPDU is required to specify how the SPDU can be
 used to determine an OBJECT IDENTIFIER (for example, by including the
 full OBJECT IDENTIFIER in the SPDU, or by including a RELATIVE-OID with
 clear instructions about how a full OBJECT IDENTIFIER can be obtained from
 the RELATIVE-OID). The SPDU is then consistent with this type if the
 OBJECT IDENTIFIER determined from the SPDU is identical to the OBJECT
 IDENTIFIER contained in this field.
 This AppExtension does not have consistency conditions with a
 corresponding CertIssueExtension. It can appear in a certificate issued
 by any CA.



```asn1
OperatingOrganizationId ::= OBJECT IDENTIFIER
```



```asn1
certExtId-OperatingOrganization ExtId ::= 1
```



```asn1
instanceOperatingOrganizationCertExtensions CERT-EXT-TYPE ::= {
  ID      certExtId-OperatingOrganization 
  APP     OperatingOrganizationId
  ISSUE   NULL
  REQUEST NULL
}
```

### <a name="SetCertExtensions"></a>SetCertExtensions

 This Information Object Set is a collection of Information Objects
 used to contain the AppExtension, CertIssueExtension, and
 CertRequestExtension types associated with a specific use of certificate
 extensions. In this version of this standard it only has a single entry
 instanceOperatingOrganizationCertExtensions.



```asn1
SetCertExtensions CERT-EXT-TYPE ::= {
  instanceOperatingOrganizationCertExtensions,
  ...
}
```




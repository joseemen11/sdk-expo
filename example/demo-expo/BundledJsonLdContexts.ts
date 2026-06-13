const personCredentialContextCid = "QmbaL4bG16tTYqAzn35qztT6cqTRZT1FMRfkcp5SLTDW2T";

export const personCredentialJsonLdContext = {
  "@context": [
    {
      "@protected": true,
      "@version": 1.1,
      id: "@id",
      type: "@type",
      PersonCredential: {
        "@context": {
          "@propagate": true,
          "@protected": true,
          "iden3-vocab": "urn:uuid:0b77399b-516d-4fe6-81dc-354131698a32#",
          xsd: "http://www.w3.org/2001/XMLSchema#",
          fullName: {
            "@id": "iden3-vocab:fullName",
            "@type": "xsd:string"
          },
          nationalIdNumber: {
            "@id": "iden3-vocab:nationalIdNumber",
            "@type": "xsd:string"
          },
          birthDate: {
            "@id": "iden3-vocab:birthDate",
            "@type": "xsd:integer"
          }
        },
        "@id": "urn:uuid:965309c9-c526-4b1d-92d7-46b0580849d1"
      }
    }
  ]
};

export const bundledJsonLdContexts: Record<string, unknown> = {
  [`https://ipfs.io/ipfs/${personCredentialContextCid}`]: personCredentialJsonLdContext,
  [`ipfs://${personCredentialContextCid}`]: personCredentialJsonLdContext,
  [personCredentialContextCid]: personCredentialJsonLdContext
};

# Creating a DID Document

A DID document is used to prove the existence and control of a DID(Decentralized Identifier). Besides other important functions it helps expose the public keys in a standards compliant way leading to interoperability. Thus, a Signed Document such as a Verifiable Credential can be assured of coming from the same source and without any unwanted tampering.

# Steps

The below steps have been written with for hosting a Ed25519VerificationKey2020 in a DID format. For other VerificationKeys please look through their specs and contribute back to this document.

**Pre-requisites**: A running Certify setup with an initialized DataProviderPlugin implementation(CertifyIssuer configured) configured and enabled.
Optional: An identity Holder, an identity Verifier

1. Get the Certificate for the KeyPair which was used to sign the Verifiable Credential from Certify. For Ed25519 key the applicationId & referenceId pair are "CERTIFY_MOCK_ED25519" & "ED25519_SIGN"

```bash
# This example demonstrates it for an Ed25519 Key created using github.com/mosip/keymanager
# If you've created a keypair with another applicationId & referenceId, do update it accordingly.

$ curl "https://${CERTIFY_HOST}/v1/certify/system-info/certificate?applicationId=CERTIFY_MOCK_ED25519&referenceId=ED25519_SIGN"
{
  "responseTime": "2024-11-28T12:48:36.299Z",
  "response": {
    "certificate": "-----BEGIN CERTIFICATE-----[REDACTED]\n\[REDACTED]\n\[REDACTED]\n-----END CERTIFICATE-----\n",
    "certSignRequest": null,
    "issuedAt": "2024-11-04T04:12:39.000Z",
    "expiryAt": "2026-11-04T04:12:39.000Z",
    "timestamp": "2024-11-28T12:48:35.689Z"
  },
  "errors": []
}
```

2. Place the Certificate in a file and convert it into a public key after it's represented properly in a file.

```bash
$ echo "-----BEGIN CERTIFICATE-----[REDACTED]\n\[REDACTED]\n\[REDACTED]\n-----END CERTIFICATE-----\n" > cert.pem
$ openssl x509 -pubkey -noout -in cert.pem > cert-pub.pem
```

3. Get the public key and use the [multibase.py](../utils/multibase-script/multibase.py) and run this script.

```bash
# NOTE: You may have to do this in your own python virtual environment and install requisite dependencies
#       Please refer to your Python Virtual Env Manager's documentation for this to get started.

$ python3 multibase.py cert-pub.pem
Loaded PEM public key from: cert-pub.pem
Multibase: [REDACTED]
Raw key length: 32
Raw key hex: [REDACTED]
Original key length: 32
Original key hex: [REDACTED]
Keys match: True
```

4. Copy the Multibase value and create a DID document.

```bash
# this example demonstrates using the an example DID hosted on https://example.github.io/DID/acme
$ cat did.json
{
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:web:vharsh.github.io:DID:harsh",
    "alsoKnownAs": [
        "admin@example.com"
    ],
    "service": [],
    "verificationMethod": [
        {
            "id": "did:web:example.github.io:DID:acme#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
            "controller": "did:web:example.github.io:DID:acme",
            "publicKeyMultibase": "[REDACTED]"

        }
    ],
    "authentication": [
        "did:web:example.github.io:DID:acme#key-0"
    ],
    "assertionMethod": [
        "did:web:example.github.io:DID:acme#key-0"
    ]
}
$
```

5. Host the DID document on the matching HTTPS domain and verify if the `did.json` document is hosted correctly via a DID Resolver such as [Uniresolver](https://dev.uniresolver.io/).

```bash
$ curl https://example.github.io/DID/acme
{
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "id": "did:web:example.github.io:DID:acme",
    "alsoKnownAs": [
        "admin@example.com"
    ],
    "service": [],
    "verificationMethod": [
        {
            "id": "did:web:example.github.io:DID:acme#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
            "controller": "did:web:example.github.io:DID:acme",
            "publicKeyMultibase": "[REDACTED]"
        }
    ],
    "authentication": [
        "did:web:example.github.io:DID:acme#key-0"
    ],
    "assertionMethod": [
        "did:web:example.github.io:DID:acme#key-0"
    ]
}
```

# Specifications(for Further reading & better understanding)

For a more detailed understanding please go through the below specs

- [Ed25519Signature2020Algorithm Spec](https://www.w3.org/community/reports/credentials/CG-FINAL-di-eddsa-2020-20220724/#ed25519verificationkey2020)
- [did:web spec](https://w3c-ccg.github.io/did-method-web/)
- [DID Core spec](https://www.w3.org/TR/did-core/)


# Contributing

Please feel free to raise PRs to improve the docs or raise issues on the [MOSIP Community](https://community.mosip.io/) if you have doubts.

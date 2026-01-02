# Claim 169 QR Code Support (Draft)

Inji Certify now includes support for generating and embedding QR codes in Verifiable Credentials (VCs). This feature enhances the usability and accessibility of digital credentials by allowing easy scanning and verification through QR code technology.

## Key Features
- **QR Code Generation:** Inji Certify can generate QR codes that encapsulate the essential data of a Verifiable Credential.
- **Embedding in Credentials:** The generated QR codes can be embedded directly into the visual representation of the credential, making it easy for users to present and share their credentials.
- **Customizable QRs:** Administrators can configure the data encoded in the QR codes to meet specific requirements.

## How to Use QR Code Support
1. **Enable QR Code Feature:** To enable QR code support, ensure that while adding the credential configuration, proper QR code template should be added in the `qr_settings` column of `credential_config` table.
*Eg:*
    ```json
    [
      {
        "Full Name": "${fullName}",
        "Phone Number": "${mobileNumber}",
        "Date Of Birth": "${dateOfBirth}"
      }
    ]
    ```
2. **Issue Credentials with QR Codes:** When issuing a Verifiable Credential, ensure that the VC template should have placeholders for the QR code with proper labels.
*Eg:*
    ```json
    {
      "credentialSubject": {
        "id": "${_holderId}",
        "fullName": "${fullName}",
        "mobileNumber": "${mobileNumber}",
        "dateOfBirth": "${dateOfBirth}",
        "identityQRCode": $claim_169_values[0]
      }
    }
    ```
3. **Scan and Verify:** Users can scan the QR code using compatible devices to quickly access and verify the QR code and extract the identity data.

## Enabling QR Code Feature
To enable QR code support in your credential configurations, you need to include the `qrSettings` object in your credential configuration JSON.

1. `credential_config` has a column named `qr_settings` of type `jsonb`. It is an optional field. It accepts a list of objects as a value such that each object corresponds to a single QR-code data.
2. Additionally, `credential_config` also contains `qr_signature_algo` column which accepts String values. The value of this column should be a valid signature algorithm supported by Inji Certify for signing the QR code data. This field is also optional.
3. If the `qr_settings` field is not provided during the creation of a credential configuration, QR code generation will be disabled by default for that configuration.
4. If the `qr_settings` field is provided, then QR code will be signed using the algorithm specified in `qr_signature_algo`. If `qr_signature_algo` is not provided, a `signature_algo` will be used to sign the QR code.
5. Below is an example of how to include `qr_settings` and `qr_signature_algo` in your credential configuration JSON:
```json
{
  "credentialFormat": "vc+sd-jwt",
  "qrSettings": [
    {
      "Full Name": "${fullName}",
      "Phone Number": "${mobileNumber}",
      "Date Of Birth": "${dateOfBirth}"
    },
    {
      "Face": {
        "Data": "${face}",
        "Data format": "Image",
        "Data sub format": "JPEG"
      },
      "Full Name": "${fullName}",
      "Date Of Birth": "${dateOfBirth}"
    }
  ],
  "qr_signature_algo": "ES256"
}
```
6. The qrCode data will be evaluated by merging velocity template with the velocity context map containing the same data provided by the data provider plugin for the credential issuance.
7. The velocity template will look like below for integrating the QR code data with the VC (This is with reference to the above `qrSettings` example):
```json
{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://piyush7034.github.io/my-files/farmer.json"
        ],
        "issuer": "${_issuer}",
        "type": [
            "VerifiableCredential",
            "FarmerCredential"
        ],
        "issuanceDate": "${validFrom}",
        "expirationDate": "${validUntil}",
        "credentialSubject": {
            "id": "${_holderId}",
            "fullName": "${fullName}",
            "mobileNumber": "${mobileNumber}",
            "dateOfBirth": "${dateOfBirth}",
            "gender": "${gender}",
            "state": "${state}",
            "identityQRCode": $claim_169_values[0],
            "faceQRCode": $claim_169_values[1]
        }
    }
```
8. In the above example, `identityQRCode` and `faceQRCode` are the fields in the credential subject where the generated QR code data will be embedded. The `$claim_169_values` is a list that contains the generated QR code data corresponding to each object defined in the `qrSettings`.

**Note:** To be completed post Pixel Pass and keymanager integration for QR code signing
 - After the QR code data is generated based on the `qrSettings`, it will be integrated with `Pixel Pass` and keymanager to convert each QR object into a signed QR code i.e `CWT`.
 - After the QR code is signed, it will then be integrated into the VC as shown in the velocity template above.
 - The rest of the VC issuance flow will remain the same as before.
 - The VC with embedded QR codes can be verified by any compatible verifier that supports QR code verification.
 - The respective context should be updated accordingly to accommodate the QR code keys in the credential subject.

# VC Revocation Feature

**Note**: This feature is currently in experimental mode and may change in future releases.

This document explains how the Credential Status feature works in Inji Certify. This feature lets you revoke or suspend verifiable credentials (VCs) in a privacy-preserving and scalable way, using a W3C-compliant status list.

---

## Overview

With this feature, the system can:

- Issue and manage [BitstringStatusListCredential](https://www.w3.org/TR/vc-bitstring-status-list/) credentials.
- Assign and track a unique status index for each credential.
- Update the status of credentials (for example, to revoke or suspend them).
- Store and retrieve status information efficiently.
- Add status information directly into each issued credential.

---

## Key Data and Storage

- **Status List Credential**: Stores the status list, its purpose (like revocation), and its current state.
- **Ledger**: Keeps a record of each issued credential, including its status and searchable attributes.
- **Credential Status Transaction**: Logs every status change (such as a revocation) for tracking and audit.

**Database tables used:**

- `status_list_credential`
- `status_list_available_indices`
- `ledger`
- `credential_status_transaction`

---

## Status List Credential Structure

A status list credential is a special Verifiable Credential with this structure:

```json
{
  ....
    "@context": [
       "https://www.w3.org/ns/credentials/v2"
    ],
  "credentialStatus": {
    "statusPurpose": "revocation",
    "statusListIndex": "10",
    "id": "https://some.example-service.com/v1/certify/status-list/45564e0c-27c9-4a83-bc87-a0ad1bce79d1#10",
    "type": "BitstringStatusListEntry",
    "statusListCredential": "https://some.example-service.com/v1/certify/status-list/45564e0c-27c9-4a83-bc87-a0ad1bce79d1"
  },
  "proof": { ... },
  ...
}
```

---

## How It Works

### 1. Issuing a Credential with Status

- When a new credential is issued, the system:
    - Finds or creates a status list for the required purpose (like revocation).
    - Assigns the next available index in the list to the credential.
    - Adds a `credentialStatus` section to the credential, for example:
      ```json
      "credentialStatus": {
        "id": "<status-list-url>#<index>",
        "type": "BitstringStatusListEntry",
        "statusPurpose": "<revocation>",
        "statusListIndex": "<index>",
        "statusListCredential": "<status-list-url>"
      }
      ```
    - Saves the credential and its status details in the ledger.

### 2. Retrieving a Status List

- You can fetch a status list credential as JSON using the API endpoint:  
  `/credentials/status-list/{id}`
- You can fetch the ledger entry for the credential using `/ledger-search` endpoint to get the status information and other details. Indexed attributes can be used to filter the search results.
  - Sample request of ledger search : 
    ```json
    {
      "credentialId": "afce16e8-02ac-4210-80d9-a0a20132bda3",
      "issuerId": "did:web:sample.github.io:my-files:sample",
      "credentialType": "FarmerCredential,VerifiableCredential",
      "indexedAttributesEquals": {
        "key1": "Bengaluru",
        "key2": "Karnataka"
      }
    }
    ```

  - Sample response of ledger search : 
      ```json
      [
        {
          "credentialId": "afce16e8-02ac-4210-80d9-a0a20132bda3",
          "issuerId": "did:web:sample.github.io:my-files:sample",
          "statusListCredentialUrl": "7bf52e81-f3bb-40ec-a0f9-a714847fd067",
          "statusListIndex": 5,
          "statusPurpose": "revocation",
          "issueDate": "2025-08-07T11:57:39",
          "expirationDate": null,
          "credentialType": "MockVerifiableCredential,VerifiableCredential",
          "statusTimestamp": "2025-08-07T11:57:39"
        }
      ]
      ```

### 3. Updating Credential Status

- To change the status (for example, to revoke a credential), use the API endpoint:  
  `/credentials/status`  
  Provide:
    - The credential’s ID
    - The credential status details (purpose, status list, index)
    - The new status (true for revoked/suspended, false for active)
- The system records this change for audit and updates the ledger.

---

## Configuration

Add these properties to your application configuration:

```properties
mosip.certify.status-list.signature-crypto-suite=Ed25519Signature2020
mosip.certify.status-list.signature-algo=EdDSA
mosip.certify.statuslist.size-in-kb=16
mosip.certify.data-provider-plugin.credential-status.supported-purposes={'revocation'}
```

---

## Enabling the Feature

1. **Database Setup**: Make sure the following tables exist:
    - `status_list_credential`
    - `status_list_available_indices`
    - `ledger`
    - `credential_status_transaction`

2. **Configuration**: Set the required properties as shown above.

3. **API Usage**:
    - Use `/credentials/status-list/{id}` to fetch status list credentials.
    - Use `/credentials/status` to update the status of a credential.
    - Use `/ledger-search` to retrieve credentials and their status information.

For more details on the API endpoints and request/response formats, refer to the [Inji Certify API documentation](https://mosip.stoplight.io/docs/inji-certify).

---

## Notes

- Only the `BitstringStatusListCredential` type is supported.
- To activate this feature, you must configure the application with the required properties. Without these, the feature will not work.
- The size of each status list can be configured.
- Only the described flows and fields are implemented. This feature is currently in experimental mode and may change in future releases.

---

## References

- [W3C VC Status List 2021](https://www.w3.org/TR/vc-bitstring-status-list/)
- [VC Data Model v2](https://www.w3.org/TR/vc-data-model-2.0/)

---
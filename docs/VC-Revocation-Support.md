# VC Revocation Feature

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
  _Note: The Status List Credential is now managed independently and is not directly tied to the ledger._
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

## How It Works
1. **Issuing a Credential with Status**
  - When a new credential is issued, the system:
  - Finds or creates a status list for the required purpose (like revocation).
  - The status list is managed independently and does not require a ledger entry.
  - Assigns the next available index in the list to the credential.
  - Adds a credentialStatus section to the credential, for example:

```json
"credentialStatus": {
  "id": "<status-list-url>#<index>",
  "type": "BitstringStatusListEntry",
  "statusPurpose": "<revocation>",
  "statusListIndex": "<index>",
  "statusListCredential": "<status-list-url>"
}
```
  - Saves the credential and its status details.

```mermaid
  sequenceDiagram
    participant Client as 🌐 Client
    box Inji Certify #E6F3FF
    participant CredentialAPI as 🔗 Credential API
    participant CredentialConfiguration as ⚙️ Credential Configuration
    participant DataProviderPlugin as 🔌 Data Provider Plugin
    participant VelocityTemplatingEngine as ⚙️ Velocity Templating Engine
    participant W3CJsonLdCredential as 🔐 W3CJsonLdCredential
    participant StatusListCredentialService as 📜 StatusListCredentialService
    participant Database as 🗄️ Database
    end

    Client->>CredentialAPI: Request VC Issuance (format: ldp_vc)

    CredentialAPI->>CredentialConfiguration: Validate request & get config
    CredentialConfiguration-->>CredentialAPI: Return success & config

    CredentialAPI->>DataProviderPlugin: Request data
    DataProviderPlugin-->>CredentialAPI: Return raw data

    CredentialAPI->>VelocityTemplatingEngine: Format raw data with template
    VelocityTemplatingEngine-->>CredentialAPI: Return unsigned VC data

    CredentialAPI->>W3CJsonLdCredential: Instantiate with unsigned data
    W3CJsonLdCredential-->>CredentialAPI: Return unsigned VC object

    opt W3C Data Model 2.0 Context is present
        CredentialAPI->>StatusListCredentialService: addCredentialStatus(unsigned VC)

        note right of StatusListCredentialService: Generate and sign the StatusList VC
        StatusListCredentialService->>StatusListCredentialService: Generate BitStringStatusList VC
        StatusListCredentialService->>W3CJsonLdCredential: Sign StatusList VC
        W3CJsonLdCredential-->>StatusListCredentialService: Return signed StatusList VC

        StatusListCredentialService->>Database: Save signed StatusList VC in Status List Credential
        Database-->>StatusListCredentialService: Confirm save

        note right of StatusListCredentialService: Update original VC with status
        StatusListCredentialService->>StatusListCredentialService: Add credentialStatus property to original VC

        alt mosip.certify.issuer.ledger.enabled = true
            StatusListCredentialService->>Database: Save status details to Ledger
            Database-->>StatusListCredentialService: Confirm save
        else mosip.certify.issuer.ledger.enabled = false
            Note over StatusListCredentialService: Skip saving status details to Ledger
        end

        StatusListCredentialService-->>CredentialAPI: Return updated unsigned VC
    end

    CredentialAPI->>W3CJsonLdCredential: addProof(final unsigned VC)
    W3CJsonLdCredential-->>CredentialAPI: Return signed VC

    CredentialAPI-->>Client: Return final signed ldp_vc

```

2. **Retrieving a Status List**
   - You can fetch a status list credential as JSON using the API endpoint: /credentials/status-list/{id}
   - This operation is independent of the ledger and only requires the status list ID.
   - Sequence diagram for status list retrieval:
```mermaid
sequenceDiagram
    participant Client as 🌐 Client
    box Inji Certify #E6F3FF
    participant Controller as 🔗 CredentialStatusController
    participant Service as ⚙️ StatusListCredentialService
    participant Repository as 🗄️ Repository/Database
    end

    Client->>Controller: GET /credentials/status-list/{id}
    Controller->>Service: getStatusListCredential(id)
    Service->>Repository: findById(id)
    Repository-->>Service: Optional<StatusListCredential>

    alt Status List Found
        Service->>Service: Parse VC Document
        Service-->>Controller: VC Document (JSON)
        Controller-->>Client: 200 OK
    else Status List Not Found
        Service-->>Controller: CertifyException
        Controller-->>Client: 404 Not Found
    end
```
  - You can fetch the ledger entry for the credential using /ledger-search endpoint to get the status information and other details. Indexed attributes can be used to filter the search results.
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
Sample response of ledger search :
  - `/ledger-search`
```json
  [
    {
      "credentialId": "afce16e8-02ac-4210-80d9-a0a20132bda3",
      "issuerId": "did:web:sample.github.io:my-files:sample",
      "statusListCredentialUrl": "7bf52e81-f3bb-40ec-a0f9-a714847fd067",
      "statusListIndex": 5,
      "statusPurpose": "revocation",
      "issueDate": "2025-08-07T11:57:39",
      "credentialType": "MockVerifiableCredential,VerifiableCredential",
      "statusTimestamp": "2025-08-07T11:57:39"
    }
  ]
```
  - `/v2/ledger-search`
```json
    [
      {
        "credentialId": "afce16e8-02ac-4210-80d9-a0a20132bda3",
        "issuerId": "did:web:sample.github.io:my-files:sample",
        "statusListCredentialUrl": "7bf52e81-f3bb-40ec-a0f9-a714847fd067",
        "statusListIndex": 5,
        "statusPurpose": "revocation",
        "issuanceDate": "2025-08-07T11:57:39",
        "credentialType": "MockVerifiableCredential,VerifiableCredential",
        "statusTimestamp": "2025-08-07T11:57:39"
      }
    ]
```

**Ledger Test Scenarios**
  - When `credentialId` is not provided during ledger search, the system returns all credentials matching the other criteria along with their status information.
  - `credentialId` is same as the `id` of the issued VC. So if the VC does not have id, then `credentialId` in ledger will be null.
  - If statusList is not enabled, then `credentialStatusDetail` will be empty for such credentials.

**Sequence diagram for Ledger Search** :
```mermaid
  sequenceDiagram
      participant Client as 🌐 Client
      box Inji Certify #E6F3FF
      participant Controller as 🔗 CredentialLedgerController
      participant Service as ⚙️ CredentialLedgerServiceImpl
      participant Repository as 🗄️ LedgerRepository
      end
      participant Database as 💾 Database

      Client->>Controller: POST /ledger-search
      Note over Client,Controller: CredentialLedgerSearchRequest with indexed attributes

      Controller->>Service: searchCredentialLedger(request)

      Service->>Service: validateSearchRequest(request)
      Note over Service: Check if indexed attributes are valid and not empty

      Service->>Repository: findBySearchRequest(request)
      Repository->>Database: Query ledger table with search criteria
      Database-->>Repository: List<Ledger> records
      Repository-->>Service: List<Ledger> records

      alt No Records Found
          Service-->>Controller: Collections.emptyList()
          Controller-->>Client: 204 No Content
      else Records Found
          Service->>Service: mapToSearchResponse(records)
          Note over Service: Map Ledger entities to CredentialStatusResponse DTOs
          Service-->>Controller: List<CredentialStatusResponse>
          Controller-->>Client: 200 OK with credential status list
      end
```

3. **Updating Credential Status**
   - To change the status (for example, to revoke a credential), use the API endpoint: /credentials/status
   - The system updates the status list independently of the ledger.
   
    **Provide**:
     - For `/credential/status` - credentialId is mandatory
     - For `/credentials/v2/status` - The credential status details (statusListCredentialId, statusListIndex) inside credentialStatus is mandatory.
- The system records this change for audit and adds the entry in `credential_status_transaction` table.
- Sequence diagram for updating credential status:
```mermaid
sequenceDiagram
    participant Client as 🌐 Client
    box Inji Certify #E6F3FF
    participant Controller as 🔗 CredentialStatusController
    participant Service as ⚙️ CredentialStatusServiceImpl
    participant LedgerRepo as 🗄️ LedgerRepository
    participant StatusRepo as 🗄️ CredentialStatusTransactionRepository
    end

    %% v1 endpoint flow
    Client->>Controller: POST /credentials/status (credentialId mandatory)
    Controller->>Service: updateCredentialStatusV1(request)
    Service->>LedgerRepo: findByCredentialId(credentialId)
    LedgerRepo-->>Service: Optional<Ledger>
    alt Credential Found
        Service->>Service: Create CredentialStatusTransaction
        Service->>StatusRepo: save(transaction)
        StatusRepo-->>Service: CredentialStatusTransaction with timestamp
        Service-->>Controller: CredentialStatusResponse
        Controller-->>Client: 200 OK
    else Credential Not Found
        Service-->>Controller: ResponseStatusException (404)
        Controller-->>Client: 404 Not Found
    end

    %% v2 endpoint flow
    Client->>Controller: POST /credentials/v2/status (credentialStatus mandatory)
    Controller->>Service: updateCredentialStatusV2(request)
    Service->>LedgerRepo: findByStatusListCredentialIdAndIndex(statusListCredentialId, statusListIndex)
    LedgerRepo-->>Service: Optional<Ledger>
    alt Credential Found
        Service->>Service: Create CredentialStatusTransaction
        Service->>StatusRepo: save(transaction)
        StatusRepo-->>Service: CredentialStatusTransaction with timestamp
        Service-->>Controller: CredentialStatusResponse
        Controller-->>Client: 200 OK
    else Credential Not Found
        Service-->>Controller: ResponseStatusException (404)
        Controller-->>Client: 404 Not Found
    end
```

4. **Status List Update Batch Job**
   - The batch job processes status changes and updates the status lists independently.
   - Ledger entries are not required for status list updates.
   - Sequence diagram for the batch job:
```mermaid
  sequenceDiagram
      participant Scheduler as 🕐 Scheduler
      participant BatchJob as 🔄 StatusListUpdateBatchJob
      participant TransactionRepo as 🗄️ Transaction Repository
      participant StatusListRepo as 📋 StatusList Repository
      participant StatusListService as 🔧 StatusListCredentialService

      Note over Scheduler: Runs hourly (cron)

      Scheduler->>BatchJob: @Scheduled trigger
      BatchJob->>BatchJob: Acquire distributed lock
      BatchJob->>BatchJob: Check if job enabled

      BatchJob->>BatchJob: determineStartTime()
      BatchJob->>StatusListRepo: findMaxUpdatedTime()
      StatusListRepo-->>BatchJob: Return last update time

      BatchJob->>TransactionRepo: findTransactionsSince(startTime, batchSize)
      TransactionRepo-->>BatchJob: Return new transactions

      alt Has new transactions
          BatchJob->>BatchJob: groupTransactionsByStatusList()

          loop For each affected status list
              BatchJob->>StatusListRepo: findById(statusListId)
              StatusListRepo-->>BatchJob: Return StatusListCredential

              BatchJob->>TransactionRepo: findLatestStatusByStatusListId()
              TransactionRepo-->>BatchJob: Return current status data

              BatchJob->>BatchJob: applyTransactionUpdates()
              BatchJob->>BatchJob: generateEncodedList()

              BatchJob->>StatusListService: resignStatusListCredential()
              StatusListService-->>BatchJob: Return signed VC document

              BatchJob->>StatusListRepo: save(updated credential)
          end

          BatchJob->>BatchJob: Update lastProcessedTime
      else No new transactions
          BatchJob->>BatchJob: Skip processing
      end

      BatchJob->>BatchJob: Release lock
```


## Configuration Properties
`mosip.certify.status-list.signature-crypto-suite=Ed25519Signature2020`
`mosip.certify.status-list.signature-algo=EdDSA`
`mosip.certify.statuslist.size-in-kb=16`
`mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes={'revocation'}`

## Enabling the Feature
1. Database Setup: Make sure the following tables exist:
   - status_list_credential
   - status_list_available_indices
   - ledger
   - credential_status_transaction
2. Configuration: Set the required properties as shown above.
3. Credential Configuration: For each credential type that should support revocation, set the credentialStatusPurposes field (e.g., to revocation) in the credential-configuration API using the /credential-configurations endpoint. The value of credentialStatusPurposes must be one of the values configured in mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes. This enables VC Revocation functionality at the credential-type level.

    **Sample request to enable revocation for a credential type**:
    ```json
    {
      "credentialFormat": "ldp_vc",
      "credentialTypes": ["FarmerCredential", "VerifiableCredential"],
      "contextURLs": ["https://www.w3.org/ns/credentials/v2"],
      "signatureCryptoSuite": "Ed25519Signature2020",
      "credentialStatusPurposes": ["revocation"],
      ...
    }
    ```
4. **API Usage**:
  - Use /credentials/status-list/{id} to fetch status list credentials.
  - Use /credentials/status to update the status of a credential.
  - Use /ledger-search to retrieve credentials and their status information.

  - For more details on the API endpoints and request/response formats, refer to the Inji Certify API documentation.

For more details on the API endpoints and request/response formats, refer to the [Inji Certify API documentation](mosip.stoplight.io).

## Notes
  - The Status List Credential is now independent of the ledger.
  - Only the `BitstringStatusListCredential` type is supported.
  - To activate this feature, you must configure the application with the required properties. Without these, the feature will not work.
  - The size of each status list can be configured.
  - Only the described flows and fields are implemented. This feature is currently in experimental mode and may change in future releases.

## References
  - [W3C VC Status List 2021](https://www.w3.org/TR/vc-bitstring-status-list/)
  - [VC Data Model v2](https://www.w3.org/TR/vc-data-model-2.0/)
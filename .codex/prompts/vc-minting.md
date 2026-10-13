afterAct as a Senior QA Automation Architect and Integration Engineer specializing in MOSIP, Inji Certify, and OpenID4VCI (OID4VCI) workflows.

### Objective
Generate a comprehensive, production-ready Test Plan and Mock Service Implementation for end-to-end integration testing of a newly developed Inji Certify API Data Provider Plugin (`DmtDataProviderPlugin`).

Format your entire output as a single, fully structured Markdown (`.md`) file (e.g., `INJI_CERTIFY_DMT_TEST_PLAN.md`).

### Key Technical Context
- Ecosystem: MOSIP / Inji Certify / OpenID4VCI (OID4VCI) specification.
- Target VC Type: `ErlCredential` (Fields: `vehicleNo`, `chassisNo`, `issueDate`, `expireDate`).
- Data Provider Contract: Spring Boot plugin implementing `DataProviderPlugin` executing REST calls to DMT endpoints.

### Markdown Document Requirements & Structure

Please format the response using standard Markdown headings (`#`, `##`, `###`), code blocks (````java`, ````yaml`, ````bash`, ````json`), and bullet points. Structure the `.md` file with the following sections:

# Inji Certify DMT Plugin - End-to-End Integration Test Plan

## 1. Overview & Architecture Flow
- Brief explanation of the test flow: Test Client -> Inji Certify -> DmtDataProviderPlugin -> Mock DMT API.
- Sequence diagram or text-based flow overview.

## 2. Standalone Mock DMT API (`MockDmtApiController.java`)
- Provide full, production-ready Java code for a Spring Boot `@RestController` running on port 8085.
- Endpoints to include:
  * `GET /v1/dmt/erl?vehicleNo={id}`
- Include Bearer token validation matching configured plugin credentials.
- Return HTTP 200 with realistic mock data (`vehicleNo`, `chassisNo`, `issueDate`, `expireDate`) for `WP-CAB-1234`.
- Return HTTP 401 (Unauthorized) for invalid/missing Bearer tokens and HTTP 404 (Not Found) for unknown vehicle numbers.

## 3. Configuration Setup (`application-test.yml`)
- Full YAML configuration properties required to wire Inji Certify to the local mock service on `http://localhost:8085/`.

## 4. End-to-End Test Execution Steps
Detail step-by-step instructions covering the OpenID4VCI Pre-Authorized Code Flow:
- Step 4.1: Launch Mock DMT API & Inji Certify Service.
- Step 4.2: Generate Pre-Authorized Code (`POST /v1/certify/pre-auth-code`).
- Step 4.3: Exchange Pre-Auth Code for Access Token (`POST /oauth/token`).
- Step 4.4: Issue Verifiable Credential (`POST /credential`).
- Step 4.5: Assertions & Log Verification.

## 5. Automation Commands & Test Payloads
- Executable `cURL` scripts with exact headers, query params, and JSON bodies for Steps 4.1 through 4.4.
- Expected HTTP status codes and JSON response structures for each request. writing the full API plugin I want test flow full with pre-auth code . Write me exact steps I should test the implement. Write a dummy API for DMT
Act as a Senior Software Engineer and Enterprise/GovTech Solutions Architect with deep expertise in Java 17+, Spring Boot 3, and MOSIP / Inji ecosystem integrations (specifically Inji Certify / Inji Verify).

### Context & Goal
I am building a modular API Data Provider Plugin for a Government Department (e.g., Department of Motor Traffic - DMT) to support multiple Verifiable Credentials (VCs), specifically starting with:
1. ERL (Electronic Registration License / Vehicle Revenue License)
2. Driving License (Planned future extension)

The plugin must be extensible and easily modifiable so that adding new VC types or changing underlying endpoints requires zero modification to core dispatching logic (adhering to the Open/Closed Principle).

### Scope Constraints for Current Milestone
- Milestone 1 Target: Support fetching data for ERL only.
- Mock/Required Data Fields for ERL: `vehicleNo`, `chassisNo`, `issueDate`, `expireDate`.
- Requirement: Provide an ARCHITECTURAL PLAN ONLY. Do not write full class implementations yet.

### Key Architectural Guidelines
1. Strategy / Registry Pattern: Decouple the core `DataProviderPlugin` from specific API endpoints using a strategy dispatch registry mapped to VC types.
2. Clean Code & Enterprise Practices: Proper encapsulation, immutable DTOs/records, robust URL/header validation (CRLF injection prevention, HTTPS enforcement), fail-fast validation, structured logging, and custom exception handling (`DataProviderExchangeException`).
3. Externalized Configuration: Keep base URLs, endpoints, timeouts, and API keys strictly in Spring externalized configuration (`application.yml`).

### Output Structure Requested
Please structure your response into the following clear sections:

1. High-Level Design & Component Architecture
   - Class/Interface diagram or component flow describing how `Inji Certify` interacts with the `MasterDataProviderPlugin`, `VcDataFetcherRegistry`, and specific `VcDataFetcher` strategies.

2. Strategy & Configuration Mapping
   - Define the internal contract (`VcDataFetcher` interface) and how VC type keys (e.g., `ERL`, `DRIVING_LICENSE`) route to specific fetcher strategies.

3. Step-by-Step Code Changes Needed
   - List each Java class/interface to create or modify, outlining its primary responsibility and key methods (e.g., `ErlDataFetcher`, `DmtDataProviderPlugin`, `ErlResponseDto`).

4. Required Configuration Changes (`application.yml`)
   - Show the exact Spring Boot properties structure for endpoint base URLs, route mappings, timeouts, and feature flags.

5. Future Extension Guide
   - Concise checklist demonstrating how a developer would add the "Driving License" VC type in the future without modifying existing strategies.
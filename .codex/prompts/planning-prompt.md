# Role & Task
You are an expert developer working in the `inji-certify` repository. Inspect the codebase, analyze the architecture, and automatically create and save two Markdown files in the root directory: `code_explanation.md` and `implementation_plan.md`.

---

## Workspace Analysis Instructions
1. Search and inspect the `inji-certify` folder structure, Spring Boot application configs (`application.yml`/`properties`), JSON/YAML credential schemas, and Data Provider interfaces/plugins.
2. Identify existing database fetchers (e.g., PostgreSQL connectors) and any plugin templates or data provider interfaces (e.g., `DataProvider`, `DataFetcher`).
3. Write `code_explanation.md` and `implementation_plan.md` directly to disk in the workspace root.

---

## File 1 Output Target: `code_explanation.md`
Generate and save `code_explanation.md` with the following structure:
- **Repository Architecture & Directory Mapping**: Key modules, directories, and exact file paths for configs, VC schemas, and provider interfaces.
- **End-to-End Credential Request Flow**: Trace how an inbound request triggers a provider, fetches data, maps it into Verifiable Credential (VC) templates, and signs the payload.
- **Native Providers vs Dynamic Plugins**: Difference between built-in connectors (PostgreSQL) and how custom plugins are dynamically loaded and registered in the Spring context.

---

## File 2 Output Target: `implementation_plan.md`
Generate and save `implementation_plan.md` with the following structure:
- **Option 1: Direct Database Access Guide**: Required properties, environment variables, SQL query mapping setup, and a step-by-step checklist to onboard a read-only DB service account.
- **Option 2: Custom API Data Fetcher Plugin Guide**: Java/Kotlin interface requirements, production-ready boilerplate code (with REST execution, auth headers, error handling), compile steps (JAR), and plugin registration.
- **Decision Matrix**: Markdown table comparing Option 1 vs. Option 2 across Effort, Security, Maintenance, and Performance.
- **Local Testing & Verification**: Step-by-step instructions to test and debug both methods locally with mock DB/API endpoints.
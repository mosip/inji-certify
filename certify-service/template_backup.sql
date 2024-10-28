--
-- PostgreSQL database dump
--

-- Dumped from database version 17.0
-- Dumped by pg_dump version 17.0

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Data for Name: template_data; Type: TABLE DATA; Schema: certify; Owner: postgres
--

INSERT INTO certify.template_data (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/2018/credentials/v1', 'MockVerifiableCredential,VerifiableCredential', '{
    "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://vharsh.github.io/DID/mock-context.json"],
    "issuer": "${issuer}",
    "type": ["VerifiableCredential", "MockVerifiableCredential"],
    "issuanceDate": "${validFrom}",
    "expirationDate": "${validUntil}",
    "credentialSubject": {
        "gender": ${gender},
        "postalCode": ${postalCode},
        "fullName": ${fullName},
        "dateOfBirth": "${dateOfBirth}",
        "province": ${province},
        "phone": "${phone}",
        "addressLine1": ${addressLine1},
        "region": ${region},
        "vcVer": "${vcVer}",
        "UIN": ${UIN},
        "email": "${email}",
        "face": "${face}"
    }
}', '2024-10-22 17:08:17.826851', NULL);
INSERT INTO certify.template_data (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://vharsh.github.io/DID/mock-context.json,https://www.w3.org/ns/credentials/v2', 'MockVerifiableCredential,VerifiableCredential', '{
    "@context": [
            "https://www.w3.org/ns/credentials/v2", "https://vharsh.github.io/DID/mock-context.json"],
    "issuer": "${issuer}",
    "type": ["VerifiableCredential", "MockVerifiableCredential"],
    "validFrom": "${validFrom}",
    "validUntil": "${validUntil}",
    "credentialSubject": {
    "gender": ${gender},
        "postalCode": ${postalCode},
        "fullName": ${fullName},
        "dateOfBirth": "${dateOfBirth}",
        "province": ${province},
        "phone": "${phone}",
        "addressLine1": ${addressLine1},
        "region": ${region},
        "vcVer": "${vcVer}",
        "UIN": ${UIN},
        "email": "${email}",
        "face": "${face}"
    }
}', '2024-10-22 17:08:17.826851', NULL);
INSERT INTO certify.template_data (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://vharsh.github.io/DID/farmer.json,https://www.w3.org/2018/credentials/v1', 'FarmerProfileCredential,VerifiableCredential', '{
    "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://vharsh.github.io/DID/farmer.json"
    ],
    "issuer": "${issuer}",
    "type": [
        "VerifiableCredential",
        "FarmerProfileCredential"
    ],
    "issuanceDate": "${validFrom}",
    "expirationDate": "${validUntil}",
    "credentialSubject": {
        "id": "${id}",
        "name": "${name}",
        "dateOfBirth": "${dateOfBirth}",
        "highestEducation": "${highestEducation}",
        "maritalStatus": "${maritalStatus}",
        "typeOfHouse": "${typeOfHouse}",
        "numberOfDependents": ${numberOfDependents},
        "phoneNumber": "${phoneNumber}",
        "knowsLanguage": ${knowsLanguage},
        "works": "${works}",
        "farmingTypes": ${farmingTypes},
        "landArea": ${landArea},
        "landOwnershipType": "${landOwnershipType}",
        "primaryCropType": "${primaryCropType}",
        "secondaryCropType": "${secondaryCropType}"
    }
}
', '2024-10-24 12:32:38.065994', NULL);


--
-- PostgreSQL database dump complete
--


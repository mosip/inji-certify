CREATE DATABASE inji_certify
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TABLESPACE = pg_default
  OWNER = postgres
  TEMPLATE  = template0;

COMMENT ON DATABASE inji_certify IS 'certify related data is stored in this database';

\c inji_certify postgres

DROP SCHEMA IF EXISTS certify CASCADE;
CREATE SCHEMA certify;
ALTER SCHEMA certify OWNER TO postgres;
ALTER DATABASE inji_certify SET search_path TO certify,pg_catalog,public;

--- keymanager specific DB changes ---
CREATE TABLE certify.key_alias(
                                  id character varying(36) NOT NULL,
                                  app_id character varying(36) NOT NULL,
                                  ref_id character varying(128),
                                  key_gen_dtimes timestamp,
                                  key_expire_dtimes timestamp,
                                  status_code character varying(36),
                                  lang_code character varying(3),
                                  cr_by character varying(256) NOT NULL,
                                  cr_dtimes timestamp NOT NULL,
                                  upd_by character varying(256),
                                  upd_dtimes timestamp,
                                  is_deleted boolean DEFAULT FALSE,
                                  del_dtimes timestamp,
                                  cert_thumbprint character varying(100),
                                  uni_ident character varying(50),
                                  CONSTRAINT pk_keymals_id PRIMARY KEY (id),
                                  CONSTRAINT uni_ident_const UNIQUE (uni_ident)
);

CREATE TABLE certify.key_policy_def(
                                       app_id character varying(36) NOT NULL,
                                       key_validity_duration smallint,
                                       is_active boolean NOT NULL,
                                       pre_expire_days smallint,
                                       access_allowed character varying(1024),
                                       cr_by character varying(256) NOT NULL,
                                       cr_dtimes timestamp NOT NULL,
                                       upd_by character varying(256),
                                       upd_dtimes timestamp,
                                       is_deleted boolean DEFAULT FALSE,
                                       del_dtimes timestamp,
                                       CONSTRAINT pk_keypdef_id PRIMARY KEY (app_id)
);

CREATE TABLE certify.key_store(
                                  id character varying(36) NOT NULL,
                                  master_key character varying(36) NOT NULL,
                                  private_key character varying(2500) NOT NULL,
                                  certificate_data character varying NOT NULL,
                                  cr_by character varying(256) NOT NULL,
                                  cr_dtimes timestamp NOT NULL,
                                  upd_by character varying(256),
                                  upd_dtimes timestamp,
                                  is_deleted boolean DEFAULT FALSE,
                                  del_dtimes timestamp,
                                  CONSTRAINT pk_keystr_id PRIMARY KEY (id)
);

CREATE TABLE certify.ca_cert_store(
    cert_id character varying(36) NOT NULL,
    cert_subject character varying(500) NOT NULL,
    cert_issuer character varying(500) NOT NULL,
    issuer_id character varying(36) NOT NULL,
    cert_not_before timestamp,
    cert_not_after timestamp,
    crl_uri character varying(120),
    cert_data character varying,
    cert_thumbprint character varying(100),
    cert_serial_no character varying(50),
    partner_domain character varying(36),
    cr_by character varying(256),
    cr_dtimes timestamp,
    upd_by character varying(256),
    upd_dtimes timestamp,
    is_deleted boolean DEFAULT FALSE,
    del_dtimes timestamp,
    ca_cert_type character varying(25),
    CONSTRAINT pk_cacs_id PRIMARY KEY (cert_id),
    CONSTRAINT cert_thumbprint_unique UNIQUE (cert_thumbprint,partner_domain)

);

CREATE TABLE certify.rendering_template (
                                    id varchar(128) NOT NULL,
                                    template VARCHAR NOT NULL,
                                    cr_dtimes timestamp NOT NULL,
                                    upd_dtimes timestamp,
                                    CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS certify.credential_config (
    credential_config_key_id VARCHAR(255) NOT NULL UNIQUE,
    config_id VARCHAR(255),
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
    vct VARCHAR,
    context VARCHAR NOT NULL,
    credential_type VARCHAR NOT NULL,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR NOT NULL,
    key_manager_app_id VARCHAR(36) NOT NULL,
    key_manager_ref_id VARCHAR(128),
    signature_algo VARCHAR(36),
    sd_claim VARCHAR,
    display JSONB NOT NULL,
    display_order TEXT[] NOT NULL,
    scope VARCHAR(255) NOT NULL,
    cryptographic_binding_methods_supported TEXT[] NOT NULL,
    credential_signing_alg_values_supported TEXT[] NOT NULL,
    proof_types_supported JSONB NOT NULL,
	credential_subject JSONB,
	claims JSONB,
    plugin_configurations JSONB,
	cr_dtimes TIMESTAMP NOT NULL,
    upd_dtimes TIMESTAMP,
    CONSTRAINT pk_config_id PRIMARY KEY (context, credential_type, credential_format)
);

INSERT INTO certify.credential_config (
    credential_config_key_id,
    config_id,
    status,
    vc_template,
    doctype,
    vct,
    context,
    credential_type,
    credential_format,
    did_url,
    key_manager_app_id,
    key_manager_ref_id,
    signature_algo,
    sd_claim,
    display,
    display_order,
    scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    credential_subject,
    claims,
    plugin_configurations,
    cr_dtimes,
    upd_dtimes
)
VALUES (
    'FarmerCredential',
    gen_random_uuid()::VARCHAR(255),  -- generating a unique config_id
    'active',  -- assuming an active status
    '{
          "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://piyush7034.github.io/my-files/farmer.json",
              "https://w3id.org/security/suites/ed25519-2020/v1"
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
              "district": "${district}",
              "villageOrTown": "${villageOrTown}",
              "postalCode": "${postalCode}",
              "landArea": "${landArea}",
              "landOwnershipType": "${landOwnershipType}",
              "primaryCropType": "${primaryCropType}",
              "secondaryCropType": "${secondaryCropType}",
              "face": "${face}",
              "farmerID": "${farmerID}"
          }
     }
    ',  -- the VC template from the JSON
    NULL,  -- doctype from JSON
    NULL,  -- vct for SD-JWT VC
    'https://www.w3.org/2018/credentials/v1',  -- context as comma-separated string
    'FarmerCredential,VerifiableCredential',  -- credential_type as comma-separated string
    'ldp_vc',  -- credential_format
    'did:web:mosip.github.io:inji-config:vc-local-ed25519#key-0',  -- did_url
    'CERTIFY_VC_SIGN_ED25519',  -- key_manager_app_id
    'ED25519_SIGN',  -- key_manager_ref_id (optional)
    'EdDSA',  -- signature_algo (optional)
    NULL,  -- sd_claim (optional)
    '[{"name": "Farmer Verifiable Credential", "locale": "en", "logo": {"url": "https://example.com/logo.png", "alt_text": "Farmer Credential Logo"}, "background_color": "#12107c", "text_color": "#FFFFFF"}]'::JSONB,  -- display
    ARRAY['fullName', 'mobileNumber', 'dateOfBirth', 'gender', 'state', 'district', 'villageOrTown', 'postalCode', 'landArea', 'landOwnershipType', 'primaryCropType', 'secondaryCropType', 'farmerID'],  -- display_order
    'farmer_identity_vc',  -- scope
    ARRAY['did:jwk'],  -- cryptographic_binding_methods_supported
    ARRAY['Ed25519Signature2020'],  -- credential_signing_alg_values_supported
    '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB,  -- proof_types_supported
    '{"fullName": {"display": [{"name": "Full Name", "locale": "en"}]}, "phone": {"display": [{"name": "Phone Number", "locale": "en"}]}, "dateOfBirth": {"display": [{"name": "Date of Birth", "locale": "en"}]}, "gender": {"display": [{"name": "Gender", "locale": "en"}]}}'::JSONB,  -- credential_subject
    NULL,  -- claims (optional)
    '[{"mosip.certify.mock.data-provider.csv.identifier-column": "id", "mosip.certify.mock.data-provider.csv.data-columns": "id,fullName,mobileNumber,dateOfBirth,gender,state,district,villageOrTown,postalCode,landArea,landOwnershipType,primaryCropType,secondaryCropType,face,farmerID", "mosip.certify.mock.data-provider.csv-registry-uri": "/home/mosip/config/farmer_identity_data.csv"}]'::JSONB,  -- plugin_configurations
    NOW(),  -- cr_dtimes
    NULL  -- upd_dtimes (optional)
);

INSERT INTO certify.credential_config (
    credential_config_key_id,
    config_id,
    status,
    vc_template,
    doctype,
    vct,
    context,
    credential_type,
    credential_format,
    did_url,
    key_manager_app_id,
    key_manager_ref_id,
    signature_algo,
    sd_claim,
    display,
    display_order,
    scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    credential_subject,
    claims,
    plugin_configurations,
    cr_dtimes,
    upd_dtimes
)
VALUES (
    'FarmerCredential_ldp_vc_DM1.1',
    gen_random_uuid()::VARCHAR(255),  -- generating a unique config_id
    'active',  -- assuming an active status
    '{
          "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://piyush7034.github.io/my-files/farmer.json",
              "https://w3id.org/security/suites/ed25519-2020/v1"
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
              "district": "${district}",
              "villageOrTown": "${villageOrTown}",
              "postalCode": "${postalCode}",
              "landArea": "${landArea}",
              "landOwnershipType": "${landOwnershipType}",
              "primaryCropType": "${primaryCropType}",
              "secondaryCropType": "${secondaryCropType}",
              "face": "${face}",
              "farmerID": "${farmerID}"
          }
     }
    ',  -- the VC template from the JSON
    NULL,  -- doctype from JSON
    NULL,  -- vct for SD-JWT VC
    'https://www.w3.org/2018/credentials/v1,https://piyush7034.github.io/my-files/farmer.json',  -- context as comma-separated string
    'FarmerCredential,VerifiableCredential',  -- credential_type as comma-separated string
    'ldp_vc',  -- credential_format
    'did:web:mosip.github.io:inji-config:vc-local-ed25519#key-0',  -- did_url
    'CERTIFY_VC_SIGN_ED25519',  -- key_manager_app_id
    'ED25519_SIGN',  -- key_manager_ref_id (optional)
    'EdDSA',  -- signature_algo (optional)
    NULL,  -- sd_claim (optional)
    '[{"name": "Farmer Verifiable Credential", "locale": "en", "logo": {"url": "https://example.com/logo.png", "alt_text": "Farmer Credential Logo"}, "background_color": "#12107c", "text_color": "#FFFFFF"}]'::JSONB,  -- display
    ARRAY['fullName', 'mobileNumber', 'dateOfBirth', 'gender', 'state', 'district', 'villageOrTown', 'postalCode', 'landArea', 'landOwnershipType', 'primaryCropType', 'secondaryCropType', 'farmerID'],  -- display_order
    'farmer_identity_vc',  -- scope
    ARRAY['did:jwk'],  -- cryptographic_binding_methods_supported
    ARRAY['Ed25519Signature2020'],  -- credential_signing_alg_values_supported
    '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB,  -- proof_types_supported
    '{"fullName": {"display": [{"name": "Full Name", "locale": "en"}]}, "phone": {"display": [{"name": "Phone Number", "locale": "en"}]}, "dateOfBirth": {"display": [{"name": "Date of Birth", "locale": "en"}]}, "gender": {"display": [{"name": "Gender", "locale": "en"}]}}'::JSONB,  -- credential_subject
    NULL,  -- claims (optional)
    '[{"mosip.certify.mock.data-provider.csv.identifier-column": "id", "mosip.certify.mock.data-provider.csv.data-columns": "id,fullName,mobileNumber,dateOfBirth,gender,state,district,villageOrTown,postalCode,landArea,landOwnershipType,primaryCropType,secondaryCropType,face,farmerID", "mosip.certify.mock.data-provider.csv-registry-uri": "/home/mosip/config/farmer_identity_data.csv"}]'::JSONB,  -- plugin_configurations
    NOW(),  -- cr_dtimes
    NULL  -- upd_dtimes (optional)
);

INSERT INTO certify.credential_config (
    credential_config_key_id,
    config_id,
    status,
    vc_template,
    doctype,
    context,
    credential_type,
    credential_format,
    did_url,
    key_manager_app_id,
    key_manager_ref_id,
    signature_algo,
    sd_claim,
    display,
    display_order,
    scope,
    cryptographic_binding_methods_supported,
    credential_signing_alg_values_supported,
    proof_types_supported,
    credential_subject,
    claims,
    plugin_configurations,
    cr_dtimes,
    upd_dtimes
)
VALUES (
    'FarmerCredential_ldp_vc_DM2.0',
    gen_random_uuid()::VARCHAR(255),  -- generating a unique config_id
    'active',  -- assuming an active status
    '{
          "@context": [
              "https://www.w3.org/ns/credentials/v2",
        "https://mosip.github.io/inji-config/contexts/farmer.json",
              "https://w3id.org/security/suites/ed25519-2020/v1"
          ],
          "issuer": "${_issuer}",
          "type": [
              "VerifiableCredential",
              "FarmerCredential"
          ],
    "validFrom": "${validFrom}",
    "validUntil": "${validUntil}",
          "credentialSubject": {
              "id": "${_holderId}",
              "fullName": "${fullName}",
              "mobileNumber": "${mobileNumber}",
              "dateOfBirth": "${dateOfBirth}",
              "gender": "${gender}",
              "state": "${state}",
              "district": "${district}",
              "villageOrTown": "${villageOrTown}",
              "postalCode": "${postalCode}",
              "landArea": "${landArea}",
              "landOwnershipType": "${landOwnershipType}",
              "primaryCropType": "${primaryCropType}",
              "secondaryCropType": "${secondaryCropType}",
              "face": "${face}",
              "farmerID": "${farmerID}"
          }
     }
    ',  -- the VC template from the JSON
    NULL,  -- doctype from JSON
    'https://piyush7034.github.io/my-files/farmer.json,https://www.w3.org/ns/credentials/v2',  -- context as comma-separated string
    'FarmerCredential,VerifiableCredential',  -- credential_type as comma-separated string
    'ldp_vc',  -- credential_format
    'did:web:mosip.github.io:inji-config:vc-local-ed25519#key-0',  -- did_url
    'CERTIFY_VC_SIGN_ED25519',  -- key_manager_app_id
    'ED25519_SIGN',  -- key_manager_ref_id (optional)
    'EdDSA',  -- signature_algo (optional)
    NULL,  -- sd_claim (optional)
    '[{"name": "Farmer Verifiable Credential", "locale": "en", "logo": {"url": "https://example.com/logo.png", "alt_text": "Farmer Credential Logo"}, "background_color": "#12107c", "text_color": "#FFFFFF"}]'::JSONB,  -- display
    ARRAY['fullName', 'mobileNumber', 'dateOfBirth', 'gender', 'state', 'district', 'villageOrTown', 'postalCode', 'landArea', 'landOwnershipType', 'primaryCropType', 'secondaryCropType', 'farmerID'],  -- display_order
    'farmer_identity_vc',  -- scope
    ARRAY['did:jwk'],  -- cryptographic_binding_methods_supported
    ARRAY['Ed25519Signature2020'],  -- credential_signing_alg_values_supported
    '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB,  -- proof_types_supported
    '{"fullName": {"display": [{"name": "Full Name", "locale": "en"}]}, "phone": {"display": [{"name": "Phone Number", "locale": "en"}]}, "dateOfBirth": {"display": [{"name": "Date of Birth", "locale": "en"}]}, "gender": {"display": [{"name": "Gender", "locale": "en"}]}}'::JSONB,  -- credential_subject
    NULL,  -- claims (optional)
    '[{"mosip.certify.mock.data-provider.csv.identifier-column": "id", "mosip.certify.mock.data-provider.csv.data-columns": "id,fullName,mobileNumber,dateOfBirth,gender,state,district,villageOrTown,postalCode,landArea,landOwnershipType,primaryCropType,secondaryCropType,face,farmerID", "mosip.certify.mock.data-provider.csv-registry-uri": "/home/mosip/config/farmer_identity_data.csv"}]'::JSONB,  -- plugin_configurations
    NOW(),  -- cr_dtimes
    NULL  -- upd_dtimes (optional)
);

INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_SERVICE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_PARTNER', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_RSA', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_ED25519', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_K1', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_R1', 1095, 60, 'NA', true, 'mosipadmin', now());

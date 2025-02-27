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

CREATE TABLE certify.credential_template(
                                    context character varying(1024) NOT NULL,
                                    credential_type character varying(512) NOT NULL,
                                    template VARCHAR NOT NULL,
                                    cr_dtimes timestamp NOT NULL default now(),
                                    upd_dtimes timestamp,
                                    CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'FarmerCredential,VerifiableCredential', '{
     "@context": [
         "https://www.w3.org/2018/credentials/v1",
         "https://mosip.github.io/inji-config/contexts/farmer.json",
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
', '2024-10-24 12:32:38.065994', NULL);

INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/ns/credentials/v2', 'FarmerCredential,VerifiableCredential', '{
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
}', '2024-10-24 12:32:38.065994', NULL);

INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1,https://mosip.github.io/inji-config/contexts/farmer.json', 'FarmerCredential,VerifiableCredential', '{
     "@context": [
         "https://www.w3.org/2018/credentials/v1",
         "https://mosip.github.io/inji-config/contexts/farmer.json",
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
', '2024-10-24 12:32:38.065994', NULL);

INSERT INTO certify.credential_template (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/ns/credentials/v2,https://mosip.github.io/inji-config/contexts/farmer.json', 'FarmerCredential,VerifiableCredential', '{
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
}', '2024-10-24 12:32:38.065994', NULL);


INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_SERVICE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_PARTNER', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_RSA', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_ED25519', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_K1', 1095, 60, 'NA', true, 'mosipadmin', now());

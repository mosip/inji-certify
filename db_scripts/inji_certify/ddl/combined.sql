DROP TABLE IF EXISTS key_alias CASCADE CONSTRAINTS;
CREATE TABLE IF NOT EXISTS key_alias(
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
DROP TABLE IF EXISTS key_policy_def CASCADE CONSTRAINTS;
CREATE TABLE IF NOT EXISTS key_policy_def(
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
DROP TABLE IF EXISTS key_store CASCADE CONSTRAINTS;
CREATE TABLE IF NOT EXISTS key_store(
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
DROP TABLE IF EXISTS rendering_template CASCADE CONSTRAINTS;
CREATE TABLE IF NOT EXISTS rendering_template (
    id UUID NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

CREATE TABLE credential_config (
    credential_config_key_id VARCHAR(255) NOT NULL UNIQUE,
    config_id VARCHAR(255),
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
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


INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_SERVICE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_PARTNER', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_RSA', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_ED25519', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_K1', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_VC_SIGN_EC_R1', 1095, 60, 'NA', true, 'mosipadmin', now());



INSERT INTO template_data (context, credential_type, template, credential_format, key_manager_app_id, key_manager_ref_id, did_url, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'FarmerCredential,VerifiableCredential', '{
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
         "id": "${id}",
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
', 'ldp_vc', 'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN','did:web:vharsh.github.io:DID:harsh#key-0', '2024-10-24 12:32:38.065994', NULL);

INSERT INTO template_data(context, credential_type, template, credential_format, key_manager_app_id, key_manager_ref_id, did_url, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/ns/credentials/v2', 'FarmerCredential,VerifiableCredential', '{
    "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://piyush7034.github.io/my-files/farmer.json",
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
        "id": "${id}",
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
}', 'ldp_vc', 'CERTIFY_VC_SIGN_ED25519','ED25519_SIGN', 'did:web:vharsh.github.io:DID:harsh', '2024-10-24 12:32:38.065994', NULL);


INSERT INTO template_data (context, credential_type, template, credential_format, key_manager_app_id, key_manager_ref_id, did_url, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'FarmerCredential,VerifiableCredential', '{
    "iss": "${_issuer}",
    "iat": ${_iat},
    "nbf": ${_nbf},
    "exp": ${_exp},
    "vc": {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential", "AadhaarCredential"],
      "credentialSubject": {
        "id": "${id}",
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
  }
', 'vc+sd-jwt', 'CERTIFY_VC_SIGN_EC_R1','EC_SECP256R1_SIGN','did:web:vharsh.github.io:DID:harsh#key-0', '2024-10-24 12:32:38.065994', NULL);


INSERT INTO template_data (context, credential_type, template, credential_format, key_manager_app_id, key_manager_ref_id, did_url, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'FarmerCredential,VerifiableCredential', '{
    "iss": "${_issuer}",
    "iat": ${_iat},
    "nbf": ${_nbf},
    "exp": ${_exp},
    "vc": {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiableCredential", "AadhaarCredential"],
      "credentialSubject": {
        "id": "${id}",
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
  }
', 'dc+sd-jwt', 'CERTIFY_VC_SIGN_EC_K1','EC_SECP256K1_SIGN','did:web:vharsh.github.io:DID:harsh#key-0', '2024-10-24 12:32:38.065994', NULL);

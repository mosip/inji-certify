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

CREATE TABLE certify.svg_template (
                                    id UUID NOT NULL,
                                    template VARCHAR NOT NULL,
                                    cr_dtimes timestamp NOT NULL,
                                    upd_dtimes timestamp,
                                    CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

CREATE TABLE certify.template_data(
                                    context character varying(1024) NOT NULL,
                                    credential_type character varying(512) NOT NULL,
                                    template VARCHAR NOT NULL,
                                    cr_dtimes timestamp NOT NULL default now(),
                                    upd_dtimes timestamp,
                                    CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

CREATE TABLE IF NOT EXISTS certify.farmer_identity
(
    individual_id character varying(100) COLLATE pg_catalog."default" NOT NULL,
    farmer_name character varying COLLATE pg_catalog."default" NOT NULL,
    phone_number character varying(10) COLLATE pg_catalog."default" NOT NULL,
    dob character varying(10) COLLATE pg_catalog."default" NOT NULL,
    identity_json character varying COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT pk_mock_id_code PRIMARY KEY (individual_id)
);




INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('1234', 'John Doe', '989898999', '1980-05-15', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Farmhouse",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "123 Farm Road",
        "addressLocality": "Farmville",
        "addressRegion": "Rural State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English"],
    "works": "Full-time",
    "farmingTypes": "Organic",
    "landArea": 50.5,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Wheat",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('12345', 'Abhishek', '7896543210', '1990-06-25', '{
    "highestEducation": "Master''s Degree",
    "maritalStatus": "Divorced",
    "typeOfHouse": "Cottage",
    "numberOfDependents": 1,
    "address": {
        "streetAddress": "234 River View Road",
        "addressLocality": "Harvest Springs",
        "addressRegion": "Western State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "German", "French"],
    "works": "Seasonal",
    "farmingTypes": ["Aquaculture", "Sedentary"],
    "landArea": 120.3,
    "landOwnershipType": "Leased",
    "primaryCropType": "Rice",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('1234567', 'Alheri Bobby', '9876543210', '1985-10-25', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Ranch",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "789 Valley Lane",
        "addressLocality": "Greenfield",
        "addressRegion": "Midwest State",
        "postalCode": "67890",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "Spanish", "Portuguese"],
    "works": "Part-time",
    "farmingTypes": ["Nomadic", "Pastoral"],
    "landArea": 75.8,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Soybeans",
    "secondaryCropType": "Wheat"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('8267411572', 'John', '9753186520', '1987-03-20', '{
    "highestEducation": "Master''s Degree",
    "maritalStatus": "Divorced",
    "typeOfHouse": "Cottage",
    "numberOfDependents": 1,
    "address": {
        "streetAddress": "234 River View Road",
        "addressLocality": "Harvest Springs",
        "addressRegion": "Western State",
        "postalCode": "12345",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "German", "French"],
    "works": "Seasonal",
    "farmingTypes": ["Aquaculture", "Sedentary"],
    "landArea": 120.3,
    "landOwnershipType": "Leased",
    "primaryCropType": "Rice",
    "secondaryCropType": "Vegetables"
}');
INSERT INTO certify.farmer_identity (individual_id, farmer_name, phone_number, dob, identity_json) VALUES ('sEaaNFRcmPMxLM9Itv_iFqDkWthO2-kFGYA6btP6y8M', 'Doe', '6789012345', '1975-10-28', '{
    "highestEducation": "Bachelor''s Degree",
    "maritalStatus": "Married",
    "typeOfHouse": "Ranch",
    "numberOfDependents": 3,
    "address": {
        "streetAddress": "789 Valley Lane",
        "addressLocality": "Greenfield",
        "addressRegion": "Midwest State",
        "postalCode": "67890",
        "addressCountry": "United States"
    },
    "knowsLanguage": ["English", "Spanish", "Portuguese"],
    "works": "Part-time",
    "farmingTypes": ["Nomadic", "Pastoral"],
    "landArea": 75.8,
    "landOwnershipType": "Self-owned",
    "primaryCropType": "Soybeans",
    "secondaryCropType": "Wheat"
}');

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
INSERT INTO certify.template_data (context, credential_type, template, cr_dtimes, upd_dtimes) VALUES ('https://www.w3.org/2018/credentials/v1', 'FarmerProfileCredential,VerifiableCredential', '{
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


INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_SERVICE', 1095, 50, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_PARTNER', 1095, 50, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_MOCK_RSA', 1095, 50, 'NA', true, 'mosipadmin', now());


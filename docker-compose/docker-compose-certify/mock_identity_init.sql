CREATE DATABASE mosip_mockidentitysystem
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TABLESPACE = pg_default
  OWNER = postgres
  TEMPLATE  = template0;

COMMENT ON DATABASE mosip_mockidentitysystem IS 'Mock identity related data is stored in this database';

\c mosip_mockidentitysystem postgres

DROP SCHEMA IF EXISTS mockidentitysystem CASCADE;
CREATE SCHEMA mockidentitysystem;
ALTER SCHEMA mockidentitysystem OWNER TO postgres;
ALTER DATABASE mosip_mockidentitysystem SET search_path TO mockidentitysystem,pg_catalog,public;

CREATE TABLE mockidentitysystem.key_alias(
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

CREATE TABLE mockidentitysystem.key_policy_def(
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

CREATE TABLE mockidentitysystem.key_store(
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

CREATE TABLE mockidentitysystem.kyc_auth(
                                            kyc_token VARCHAR(255),
                                            individual_id VARCHAR(255),
                                            partner_specific_user_token VARCHAR(255),
                                            response_time TIMESTAMP,
                                            transaction_id VARCHAR(255),
                                            validity INTEGER
);

CREATE TABLE mockidentitysystem.mock_identity(
                                                 individual_id VARCHAR(36) NOT NULL,
                                                 identity_json VARCHAR NOT NULL,
                                                 CONSTRAINT pk_mock_id_code PRIMARY KEY (individual_id)
);

INSERT INTO mockidentitysystem.KEY_POLICY_DEF(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO mockidentitysystem.KEY_POLICY_DEF(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('MOCK_AUTHENTICATION_SERVICE', 1095, 50, 'NA', true, 'mosipadmin', now());
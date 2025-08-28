CREATE DATABASE inji_mimoto
  ENCODING = 'UTF8'
  LC_COLLATE = 'en_US.UTF-8'
  LC_CTYPE = 'en_US.UTF-8'
  TABLESPACE = pg_default
  OWNER = postgres
  TEMPLATE  = template0;

COMMENT ON DATABASE inji_mimoto IS 'mimoto related data is stored in this database';

\c inji_mimoto postgres

DROP SCHEMA IF EXISTS mimoto CASCADE;
CREATE SCHEMA mimoto;
ALTER SCHEMA mimoto OWNER TO postgres;
ALTER DATABASE inji_mimoto SET search_path TO mimoto,pg_catalog,public;

--- keymanager specific DB changes ---
CREATE TABLE mimoto.key_alias(
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

CREATE TABLE mimoto.key_policy_def(
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

CREATE TABLE mimoto.key_store(
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

CREATE TABLE mimoto.ca_cert_store(
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

CREATE TABLE IF NOT EXISTS user_metadata (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    provider_subject_id character varying(255) NOT NULL,  -- Unique identifier for the provider subject
    identity_provider character varying(255) NOT NULL,  -- Unique identifier for the identity provider
    display_name TEXT NOT NULL,  -- Display name of the user
    profile_picture_url TEXT,  -- URL of the user's profile picture
    phone_number TEXT,  -- Phone number of the user
    email TEXT NOT NULL,  -- Email of the user (Required field)
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now()  -- Timestamp of last update (defaults to current time)
);

CREATE TABLE IF NOT EXISTS wallet (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    user_id character varying(36) NOT NULL,  -- Foreign key referencing user_metadata
    wallet_key TEXT NOT NULL,  -- Encrypted wallet key (retained here)
    wallet_metadata JSONB NOT NULL,  -- Metadata about the wallet, including encryption info
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES user_metadata (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS verifiable_credentials (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referring to the wallet table (wallet.id)
    credential TEXT NOT NULL,  -- Encrypted credential (using wallet_key for encryption/decryption)
    credential_metadata JSONB NOT NULL,  -- Metadata about the credential
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS proof_signing_key (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referencing the wallet table
    public_key TEXT NOT NULL,  -- Public key for wallet
    secret_key TEXT NOT NULL,  -- Secret key, encrypted using proof_signing_key
    key_metadata JSONB NOT NULL,  -- Metadata about the public and private keys
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

INSERT INTO mimoto.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('ROOT', 2920, 1125, 'NA', true, 'mosipadmin', now());
INSERT INTO mimoto.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO mimoto.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('MIMOTO', 1095, 60, 'NA', true, 'mosipadmin', now());


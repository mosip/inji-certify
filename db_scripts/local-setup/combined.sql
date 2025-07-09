Drop table if exists ca_cert_store;
CREATE TABLE ca_cert_store(
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
Drop table if exists key_alias;
CREATE TABLE key_alias(
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
Drop table if exists key_policy_def;
CREATE TABLE key_policy_def(
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
Drop table if exists key_store;
CREATE TABLE key_store(
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
Drop table if exists rendering_template;
CREATE TABLE rendering_template (
    id VARCHAR(128) NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_rendertmp_id PRIMARY KEY (id)
);
DROP TABLE IF EXISTS credential_config CASCADE CONSTRAINTS;
CREATE TABLE credential_config (
    credential_config_key_id VARCHAR(255) NOT NULL UNIQUE,
    config_id VARCHAR(255) NOT NULL,
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
    sd_jwt_vct VARCHAR,
    context VARCHAR,
    credential_type VARCHAR,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR,
    key_manager_app_id VARCHAR(36),
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
    CONSTRAINT pk_config_id PRIMARY KEY (config_id)
);

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON credential_config(credential_type, context, credential_format)
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON credential_config(sd_jwt_vct, credential_format)
WHERE sd_jwt_vct IS NOT NULL and sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON credential_config(doctype, credential_format)
WHERE doctype IS NOT NULL and doctype <> '';

INSERT INTO key_policy_def (app_id, key_validity_duration, pre_expire_days, access_allowed, is_active, cr_by, cr_dtimes)
SELECT app_id, key_validity_duration, pre_expire_days, access_allowed, is_active, cr_by, CURRENT_TIMESTAMP
FROM CSVREAD('./db_scripts/mosip_certify/dml/certify-key_policy_def.csv');
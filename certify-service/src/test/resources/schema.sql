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

CREATE TABLE  IF NOT EXISTS key_policy_def(
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
CREATE TABLE  IF NOT EXISTS key_store(
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

CREATE TABLE IF NOT EXISTS ca_cert_store(
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

CREATE TABLE IF NOT EXISTS rendering_template (
    id VARCHAR(128) NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_rendertmp_id PRIMARY KEY (id)
);

-- Changed all `JSONB` and `TEXT[]` types to VARCHAR to make it work with H2 database
CREATE TABLE IF NOT EXISTS credential_config (
    credential_config_key_id VARCHAR(255) NOT NULL UNIQUE,
    config_id VARCHAR(255),
    status VARCHAR(255),
    vc_template VARCHAR(1000),
    doctype VARCHAR(255),
    vct VARCHAR(255),
    context VARCHAR(255) NOT NULL,
    credential_type VARCHAR(255) NOT NULL,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR(255) NOT NULL,
    key_manager_app_id VARCHAR(36) NOT NULL,
    key_manager_ref_id VARCHAR(128),
    signature_algo VARCHAR(255),
    sd_claim VARCHAR(255),
    display VARCHAR NOT NULL,
    display_order VARCHAR NOT NULL,
    scope VARCHAR(255) NOT NULL,
    cryptographic_binding_methods_supported VARCHAR NOT NULL,
    credential_signing_alg_values_supported VARCHAR NOT NULL,
    proof_types_supported VARCHAR NOT NULL,
    credential_subject VARCHAR,
    claims VARCHAR,
    plugin_configurations VARCHAR,
    cr_dtimes TIMESTAMP NOT NULL,
    upd_dtimes TIMESTAMP,
    CONSTRAINT pk_config_id PRIMARY KEY (context, credential_type, credential_format)
);


INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('CERTIFY_ED25519', 1095, 60, 'NA', true, 'mosipadmin', now());
INSERT INTO certify.key_policy_def(APP_ID,KEY_VALIDITY_DURATION,PRE_EXPIRE_DAYS,ACCESS_ALLOWED,IS_ACTIVE,CR_BY,CR_DTIMES) VALUES('BASE', 1095, 60, 'NA', true, 'mosipadmin', now());

CREATE TABLE rendering_template (
    id UUID NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_rendertmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE rendering_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN rendering_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN rendering_template.template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN rendering_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN rendering_template.upd_dtimes IS 'Date when the template was last updated in table.';

CREATE TABLE credential_template(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	cr_dtimes timestamp NOT NULL default now(),
	upd_dtimes timestamp,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

COMMENT ON TABLE credential_template IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN credential_template.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN credential_template.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN credential_template.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN credential_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN credential_template.upd_dtimes IS 'Date when the template was last updated in table.';

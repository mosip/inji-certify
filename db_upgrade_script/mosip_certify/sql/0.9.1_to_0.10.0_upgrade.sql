\c inji_certify

CREATE TABLE svg_template (
    id UUID NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE svg_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN svg_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN svg_template.template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN svg_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN svg_template.upd_dtimes IS 'Date when the template was last updated in table.';

CREATE TABLE IF NOT EXISTS template_data(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	cr_dtimes timestamp NOT NULL default now(),
	upd_dtimes timestamp,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

COMMENT ON TABLE template_data IS 'Template Data: Contains velocity template for VC';

COMMENT ON COLUMN template_data.context IS 'VC Context: Context URL list items separated by comma(,)';
COMMENT ON COLUMN template_data.credential_type IS 'Credential Type: Credential type list items separated by comma(,)';
COMMENT ON COLUMN template_data.template IS 'Template Content: Velocity Template to generate the VC';
COMMENT ON COLUMN template_data.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN template_data.upd_dtimes IS 'Date when the template was last updated in table.';
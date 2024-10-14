CREATE TABLE IF NOT EXISTS template_data(
	context character varying(1024) NOT NULL,
	credential_type character varying(512) NOT NULL,
	template VARCHAR NOT NULL,
	CONSTRAINT pk_template PRIMARY KEY (context, credential_type)
);

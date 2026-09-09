UPDATE certify.credential_config
SET display = COALESCE((
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' IS NOT NULL
                           AND (elem->'logo')::jsonb ? 'url' THEN
                           jsonb_set(
                                   elem::jsonb,
                                   '{logo}',
                                   ((elem->'logo')::jsonb - 'url')
                    || jsonb_build_object('uri', (elem->'logo')::jsonb -> 'url')
                )
                       ELSE elem::jsonb
                       END
           )
    FROM jsonb_array_elements(display::jsonb) AS elem
), '[]'::jsonb)
WHERE display IS NOT NULL;

ALTER TABLE certify.credential_config
RENAME COLUMN credential_subject TO claims;
COMMENT ON COLUMN certify.credential_config.claims IS 'Claims: JSON object containing subject attributes schema.';

UPDATE certify.credential_config
SET credential_format = 'dc+sd-jwt'
WHERE credential_format = 'vc+sd-jwt';

CREATE TABLE IF NOT EXISTS certify.authorization_request_details (
    request_id      character varying(40) NOT NULL,
    transaction_id  character varying(40) NOT NULL,
    authorization_details text NOT NULL,
    expires_at      bigint NOT NULL,
    CONSTRAINT pk_authorization_request_details PRIMARY KEY (request_id)
);

COMMENT ON TABLE certify.authorization_request_details IS 'Stores VP authorization request details created by the embedded inji-verify library';
COMMENT ON COLUMN certify.authorization_request_details.request_id IS 'Unique request ID for the VP authorization request';
COMMENT ON COLUMN certify.authorization_request_details.transaction_id IS 'Transaction ID linking this request to the issuance session';
COMMENT ON COLUMN certify.authorization_request_details.authorization_details IS 'JSON blob containing full OpenID4VP authorization request details';
COMMENT ON COLUMN certify.authorization_request_details.expires_at IS 'Epoch-millis expiry of the authorization request';

CREATE INDEX IF NOT EXISTS idx_ard_transaction_id ON certify.authorization_request_details (transaction_id);

CREATE TABLE IF NOT EXISTS certify.presentation_definition (
    id                      character varying(36) NOT NULL,
    input_descriptors       text NOT NULL,
    name                    character varying(500),
    purpose                 character varying(500),
    vp_format               text,
    submission_requirements text,
    CONSTRAINT pk_presentation_definition PRIMARY KEY (id)
);

COMMENT ON TABLE certify.presentation_definition IS 'Stores Presentation Definitions used by the embedded inji-verify library';
COMMENT ON COLUMN certify.presentation_definition.id IS 'Unique identifier for the presentation definition';
COMMENT ON COLUMN certify.presentation_definition.input_descriptors IS 'JSON array of input descriptor objects defining required credential types';
COMMENT ON COLUMN certify.presentation_definition.name IS 'Human-readable name for the presentation definition';
COMMENT ON COLUMN certify.presentation_definition.purpose IS 'Human-readable purpose for which the presentation definition is used';
COMMENT ON COLUMN certify.presentation_definition.vp_format IS 'JSON describing supported VP formats and algorithms';
COMMENT ON COLUMN certify.presentation_definition.submission_requirements IS 'JSON describing submission requirement constraints';

CREATE TABLE IF NOT EXISTS certify.vc_submission (
    transaction_id character varying(40) NOT NULL,
    vc             text NOT NULL
);

COMMENT ON TABLE certify.vc_submission IS 'Stores individual VC results from VP verification by the embedded inji-verify library';
COMMENT ON COLUMN certify.vc_submission.transaction_id IS 'Transaction ID linking the VC result to the issuance session';
COMMENT ON COLUMN certify.vc_submission.vc IS 'Base64-encoded or JSON VC extracted from the verified VP token';

CREATE INDEX IF NOT EXISTS idx_vc_submission_transaction_id ON certify.vc_submission (transaction_id);

CREATE TABLE IF NOT EXISTS certify.vp_submission (
    request_id              character varying(40) NOT NULL,
    vp_token                VARCHAR NULL,
    presentation_submission text NULL,
    error                   character varying(100) NULL,
    error_description       character varying(200) NULL,
    response_code           character varying(200) NULL,
    response_code_expiry_at TIMESTAMP WITH TIME ZONE NULL,
    response_code_used      boolean DEFAULT false,
    CONSTRAINT pk_vp_submission PRIMARY KEY (request_id),
    CONSTRAINT uq_vp_submission_response_code UNIQUE (response_code)
);

COMMENT ON TABLE certify.vp_submission IS 'Stores VP token submissions received by the embedded inji-verify library';
COMMENT ON COLUMN certify.vp_submission.request_id IS 'Foreign key to authorization_request_details.request_id';
COMMENT ON COLUMN certify.vp_submission.vp_token IS 'The VP token submitted by the wallet';
COMMENT ON COLUMN certify.vp_submission.presentation_submission IS 'JSON presentation_submission descriptor from the wallet';
COMMENT ON COLUMN certify.vp_submission.error IS 'Error code if the wallet reported an error';
COMMENT ON COLUMN certify.vp_submission.error_description IS 'Human-readable error description from the wallet';
COMMENT ON COLUMN certify.vp_submission.response_code IS 'Response code for same-device flows (not used in certify)';
COMMENT ON COLUMN certify.vp_submission.response_code_expiry_at IS 'Expiry of the response code';
COMMENT ON COLUMN certify.vp_submission.response_code_used IS 'Whether the response code has been consumed';

CREATE INDEX IF NOT EXISTS idx_vp_submission_response_code ON certify.vp_submission (response_code);

UPDATE certify.credential_config
SET proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb
WHERE proof_types_supported = '{}'::jsonb;

-- Replace legacy Ed25519 with EdDSA in existing JWT proof algorithm lists
UPDATE certify.credential_config
SET proof_types_supported = jsonb_set(
        proof_types_supported,
        '{jwt,proof_signing_alg_values_supported}',
        (
            SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
            FROM (
                     SELECT
                         CASE
                             WHEN alg = '"Ed25519"'::jsonb THEN '"EdDSA"'::jsonb
                             ELSE alg
                             END AS val
                     FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
                 ) sub
        )
                            )
WHERE proof_types_supported #> '{jwt,proof_signing_alg_values_supported}' IS NOT NULL
  AND EXISTS (
      SELECT 1
      FROM jsonb_array_elements(proof_types_supported #> '{jwt,proof_signing_alg_values_supported}') AS alg
      WHERE alg = '"Ed25519"'::jsonb
  );
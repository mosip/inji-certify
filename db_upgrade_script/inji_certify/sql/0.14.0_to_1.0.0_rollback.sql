UPDATE certify.credential_config
SET display = COALESCE((
    SELECT jsonb_agg(
                   CASE
                       WHEN elem->'logo' IS NOT NULL
                           AND (elem->'logo')::jsonb ? 'uri' THEN
                           jsonb_set(
                                   elem::jsonb,
                                   '{logo}',
                                   ((elem->'logo')::jsonb - 'uri')
                    || jsonb_build_object(
                        'url',
                        (elem->'logo')::jsonb -> 'uri'
                    )
                )
                       ELSE elem::jsonb
                       END
           )
    FROM jsonb_array_elements(display::jsonb) AS elem
), '[]'::jsonb)
WHERE display IS NOT NULL;

ALTER TABLE certify.credential_config
RENAME COLUMN claims TO credential_subject;
COMMENT ON COLUMN certify.credential_config.credential_subject IS 'Credential Subject: JSON object containing subject attributes schema.';

UPDATE certify.credential_config
SET credential_format = 'vc+sd-jwt'
WHERE credential_format = 'dc+sd-jwt';

DROP INDEX IF EXISTS certify.idx_vp_submission_response_code;
DROP INDEX IF EXISTS certify.idx_vc_submission_transaction_id;
DROP INDEX IF EXISTS certify.idx_ard_transaction_id;

DROP TABLE IF EXISTS certify.vp_submission;
DROP TABLE IF EXISTS certify.vc_submission;
DROP TABLE IF EXISTS certify.presentation_definition;
DROP TABLE IF EXISTS certify.authorization_request_details;

UPDATE certify.credential_config
SET proof_types_supported = '{}'::jsonb
WHERE proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb;

-- Replace EdDSA back to Ed25519 in existing JWT proof algorithm lists
UPDATE certify.credential_config
SET proof_types_supported = jsonb_set(
        proof_types_supported,
        '{jwt,proof_signing_alg_values_supported}',
        (
            SELECT COALESCE(jsonb_agg(DISTINCT val), '[]'::jsonb)
            FROM (
                     SELECT
                         CASE
                             WHEN alg = '"EdDSA"'::jsonb THEN '"Ed25519"'::jsonb
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
      WHERE alg = '"EdDSA"'::jsonb
  );
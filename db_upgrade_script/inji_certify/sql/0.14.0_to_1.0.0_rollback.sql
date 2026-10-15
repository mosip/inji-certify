-- -------------------------------------------------------------------------------------------------
-- Rollback Script : v1.0.0 to v0.14.0
-- Release name    : 1.0.0-alpha.1, 1.0.0-rc.1
-- Database        : inji_certify
-- Purpose         : Revert schema changes introduced across the 1.0.0 pre-releases.
-- -------------------------------------------------------------------------------------------------

-- -------------------------------------------------------------------------------------------------
-- SECTION 4: Revert optional holder binding
-- -------------------------------------------------------------------------------------------------
-- Runs first: 0.14.0 requires holder binding for every credential configuration, so configurations
-- without it (NULL) get the 1.0.0 defaults, which SECTION 2 then converts to the 0.14.0 form. The
-- values mirror mosip.certify.credential-config.cryptographic-binding-methods-supported and
-- mosip.certify.credential-config.proof-types-supported in certify-default.properties; the proof
-- algorithms keep the order SECTION 2 matches on.
UPDATE certify.credential_config
SET cryptographic_binding_methods_supported = CASE
        WHEN credential_format = 'mso_mdoc' THEN ARRAY['cose_key']
        ELSE ARRAY['did:jwk', 'did:key']
    END
WHERE cryptographic_binding_methods_supported IS NULL;

UPDATE certify.credential_config
SET proof_types_supported = '{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256", "PS256", "EdDSA"]}}'::jsonb
WHERE proof_types_supported IS NULL;

ALTER TABLE certify.credential_config
    ALTER COLUMN cryptographic_binding_methods_supported SET NOT NULL;

ALTER TABLE certify.credential_config
    ALTER COLUMN proof_types_supported SET NOT NULL;

-- -------------------------------------------------------------------------------------------------
-- SECTION 1: Revert credential_config OpenID4VCI 1.0 alignment
-- Reverts: 1.0.0-alpha.1
-- -------------------------------------------------------------------------------------------------
-- Restore display logo "uri" to "url", rename claims back to credential_subject, and
-- restore the dc+sd-jwt credential format to vc+sd-jwt.
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

-- -------------------------------------------------------------------------------------------------
-- SECTION 2: Restore JWT proof signing algorithms (EdDSA -> Ed25519)
-- Reverts: 1.0.0-alpha.1
-- -------------------------------------------------------------------------------------------------
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

-- -------------------------------------------------------------------------------------------------
-- SECTION 3: Drop embedded inji-verify library tables
-- Reverts: 1.0.0-rc.1
-- -------------------------------------------------------------------------------------------------
DROP INDEX IF EXISTS certify.idx_vp_submission_response_code;
DROP INDEX IF EXISTS certify.idx_vc_submission_transaction_id;
DROP INDEX IF EXISTS certify.idx_ard_transaction_id;

DROP TABLE IF EXISTS certify.vp_submission;
DROP TABLE IF EXISTS certify.vc_submission;
DROP TABLE IF EXISTS certify.authorization_request_details;

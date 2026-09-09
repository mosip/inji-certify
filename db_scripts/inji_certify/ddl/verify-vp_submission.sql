-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- Table required by the embedded inji-verify library.
-- Stores VP submissions from the wallet during the presentation-during-issuance flow.

CREATE TABLE IF NOT EXISTS vp_submission (
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

COMMENT ON TABLE vp_submission IS 'Stores VP token submissions received by the embedded inji-verify library';
COMMENT ON COLUMN vp_submission.request_id IS 'Foreign key to authorization_request_details.request_id';
COMMENT ON COLUMN vp_submission.vp_token IS 'The VP token submitted by the wallet';
COMMENT ON COLUMN vp_submission.presentation_submission IS 'JSON presentation_submission descriptor from the wallet';
COMMENT ON COLUMN vp_submission.error IS 'Error code if the wallet reported an error';
COMMENT ON COLUMN vp_submission.error_description IS 'Human-readable error description from the wallet';
COMMENT ON COLUMN vp_submission.response_code IS 'Response code for same-device flows (not used in certify)';
COMMENT ON COLUMN vp_submission.response_code_expiry_at IS 'Expiry of the response code';
COMMENT ON COLUMN vp_submission.response_code_used IS 'Whether the response code has been consumed';

CREATE INDEX IF NOT EXISTS idx_vp_submission_response_code ON vp_submission (response_code);

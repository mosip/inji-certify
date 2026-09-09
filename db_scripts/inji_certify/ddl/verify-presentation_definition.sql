-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
--
-- Table required by the embedded inji-verify library.
-- Stores predefined Presentation Definitions used in OpenID4VP sharing.

CREATE TABLE IF NOT EXISTS presentation_definition (
    id                      character varying(36) NOT NULL,
    input_descriptors       text NOT NULL,
    name                    character varying(500),
    purpose                 character varying(500),
    vp_format               text,
    submission_requirements text,
    CONSTRAINT pk_presentation_definition PRIMARY KEY (id)
);

COMMENT ON TABLE presentation_definition IS 'Stores Presentation Definitions used by the embedded inji-verify library';
COMMENT ON COLUMN presentation_definition.id IS 'Unique identifier for the presentation definition';
COMMENT ON COLUMN presentation_definition.input_descriptors IS 'JSON array of input descriptor objects defining required credential types';
COMMENT ON COLUMN presentation_definition.name IS 'Human-readable name for the presentation definition';
COMMENT ON COLUMN presentation_definition.purpose IS 'Human-readable purpose for which the presentation definition is used';
COMMENT ON COLUMN presentation_definition.vp_format IS 'JSON describing supported VP formats and algorithms';
COMMENT ON COLUMN presentation_definition.submission_requirements IS 'JSON describing submission requirement constraints';

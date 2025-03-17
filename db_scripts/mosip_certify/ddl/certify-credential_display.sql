-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_display
-- Purpose    : Credential Display Table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE credential_display (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255),
    locale VARCHAR(255),
    logo JSONB,  -- JSONB type
    background_color VARCHAR(255),
    text_color VARCHAR(255)
);

COMMENT ON TABLE credential_display IS 'Credential Display: Contains display information for credentials.';
COMMENT ON COLUMN credential_display.id IS 'Display ID: Unique identifier for the credential display.';
COMMENT ON COLUMN credential_display.name IS 'Display Name: Name of the credential for display purposes.';
COMMENT ON COLUMN credential_display.locale IS 'Locale: Language and region code for localization.';
COMMENT ON COLUMN credential_display.logo IS 'Logo: JSON object containing logo information.';
COMMENT ON COLUMN credential_display.background_color IS 'Background Color: Color code for the credential background.';
COMMENT ON COLUMN credential_display.text_color IS 'Text Color: Color code for the credential text.';
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config
-- Purpose    : Credential Configuration Table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE credential_config (
    id VARCHAR(128) NOT NULL,
    status VARCHAR NOT NULL,
    configuration VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL default now(),
    upd_dtimes timestamp,
    CONSTRAINT pk_cred_config_id PRIMARY KEY (id)
);

COMMENT ON TABLE credential_config IS 'Credential Config: Contains details of credential configuration.';

COMMENT ON COLUMN credential_config.id IS 'Credential Config Id: Unique id assigned to save and identify configuration.';
COMMENT ON COLUMN credential_config.status IS 'Credential Config Status: Status of the credential configuration.';
COMMENT ON COLUMN credential_config.configuration IS 'Credential Config Configuration: Congiguration JSON of the new config';
COMMENT ON COLUMN credential_config.cr_dtimes IS 'Date when the config was inserted in table.';
COMMENT ON COLUMN credential_config.upd_dtimes IS 'Date when the config was last updated in table.';
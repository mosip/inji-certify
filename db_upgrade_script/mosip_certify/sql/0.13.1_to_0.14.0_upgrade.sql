-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template,credential_template, ca_cert_store
-- Purpose    : To upgrade Certify v0.12.1 changes and make it compatible with v0.13.0
--
-- Create By   	: Piyush Shukla
-- Created Date	: September-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Add qr_settings and qr_signature_algo columns to credential_config
ALTER TABLE certify.credential_config
    ADD COLUMN qr_settings JSONB,
    ADD COLUMN qr_signature_algo TEXT;

COMMENT ON COLUMN credential_config.qr_settings IS 'QR Settings: JSON object containing QR code related settings.';
COMMENT ON COLUMN credential_config.qr_signature_algo IS 'Signature algorithm used for QR code generation.';

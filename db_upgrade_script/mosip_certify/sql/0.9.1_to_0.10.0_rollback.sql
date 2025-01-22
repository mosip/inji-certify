-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template,credential_template, ca_cert_store
-- Purpose    : To remove Certify v0.10.0 changes and make DB ready for Certify v0.9.1
--
-- Create By   	: Harsh Vardhan
-- Created Date	: January-2025
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

drop table rendering_template;
drop table credential_template;
drop table ca_cert_store;

--- Keymanager policy drop ---
DELETE FROM certify.key_policy_def where APP_ID in ('CERTIFY_VC_SIGN_RSA', 'CERTIFY_VC_SIGN_ED25519', 'BASE');

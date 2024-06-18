-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------

\c mosip_certify

GRANT CONNECT
   ON DATABASE mosip_certify
   TO certifyuser;

GRANT USAGE
   ON SCHEMA certify
   TO certifyuser;

GRANT SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES
   ON ALL TABLES IN SCHEMA certify
   TO certifyuser;

ALTER DEFAULT PRIVILEGES IN SCHEMA certify
	GRANT SELECT,INSERT,UPDATE,DELETE,REFERENCES ON TABLES TO certifyuser;


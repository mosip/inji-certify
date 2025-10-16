-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : shedlock
-- Purpose    : Table for managing distributed locks using ShedLock library
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
-- Create shedlock table for distributed locking
CREATE TABLE IF NOT EXISTS shedlock (
  name VARCHAR(64),
  lock_until TIMESTAMPTZ(3) NOT NULL,
  locked_at TIMESTAMPTZ(3) NOT NULL,
  locked_by VARCHAR(255) NOT NULL,
  PRIMARY KEY (name)
);

COMMENT ON TABLE shedlock IS 'Table for managing distributed locks using ShedLock library.';
COMMENT ON COLUMN shedlock.name IS 'Unique name of the lock.';
COMMENT ON COLUMN shedlock.lock_until IS 'Timestamp until which the lock is held. NULL if not locked.';
COMMENT ON COLUMN shedlock.locked_at IS 'Timestamp when the lock was acquired. NULL if not locked.';
COMMENT ON COLUMN shedlock.locked_by IS 'Identifier of the node/process that holds the lock. NULL if not locked.';
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : rendering_template
-- Purpose    : Svg Template table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE rendering_template (
    id VARCHAR(128) NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_rendertmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE rendering_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN rendering_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN rendering_template.template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN rendering_template.cr_dtimes IS 'Date when the template was inserted in table.';
COMMENT ON COLUMN rendering_template.upd_dtimes IS 'Date when the template was last updated in table.';

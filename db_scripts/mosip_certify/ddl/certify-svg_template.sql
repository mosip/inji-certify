-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : svg_render_template
-- Purpose    : Svg Render Template table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE svg_template (
    id UUID NOT NULL,
    template VARCHAR NOT NULL,
    cr_dtimes timestamp NOT NULL,
    upd_dtimes timestamp,
    CONSTRAINT pk_svgtmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE svg_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN svg_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN svg_template.template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN svg_template.last_modified IS 'Last date when the template was modified.';



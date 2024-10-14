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

create table svg_render_template (
    id UUID NOT NULL,
    svg_template VARCHAR NOT NULL,
    template_name VARCHAR NOT NULL,
    last_modified TIMESTAMP DEFAULT NOW() NOT NULL,
    CONSTRAINT pk_svgrndrtmp_id PRIMARY KEY (id)
);

COMMENT ON TABLE svg_render_template IS 'SVG Render Template: Contains svg render image for VC.';

COMMENT ON COLUMN svg_render_template.id IS 'Template Id: Unique id assigned to save and identify template.';
COMMENT ON COLUMN svg_render_template.svg_template IS 'SVG Template Content: SVG Render Image for the VC details.';
COMMENT ON COLUMN svg_render_template.last_modified IS 'Last date when the template was modified.';



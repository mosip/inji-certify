/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.repository;

import io.mosip.certify.entity.RenderingTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RenderingTemplateRepository extends JpaRepository<RenderingTemplate, String> {
}

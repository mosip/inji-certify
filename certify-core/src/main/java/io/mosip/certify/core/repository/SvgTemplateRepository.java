/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.repository;

import io.mosip.certify.core.entity.SvgTemplate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface SvgTemplateRepository extends JpaRepository<SvgTemplate, UUID> {
}

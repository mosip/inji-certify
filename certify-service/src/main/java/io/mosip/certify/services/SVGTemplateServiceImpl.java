/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.entity.SVGTemplate;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.repository.SVGTemplateRepository;
import io.mosip.certify.core.spi.SVGTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class SVGTemplateServiceImpl implements SVGTemplateService {
    @Autowired
    SVGTemplateRepository svgRenderTemplateRepository;


    @Override
    public SVGTemplate getSvgTemplate(UUID id) {
        Optional<SVGTemplate> optional = svgRenderTemplateRepository.findById(id);
        SVGTemplate svgRenderTemplate = optional.orElseThrow(() -> new TemplateException(ErrorConstants.INVALID_TEMPLATE_ID));

        return svgRenderTemplate;

    }
}

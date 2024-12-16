/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.services.entity.RenderingTemplate;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.services.repository.RenderingTemplateRepository;
import io.mosip.certify.services.spi.RenderingTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Slf4j
@Component
public class RenderingTemplateServiceImpl implements RenderingTemplateService {
    @Autowired
    RenderingTemplateRepository svgRenderTemplateRepository;


    @Override
    public RenderingTemplate getSvgTemplate(String id) {
        Optional<RenderingTemplate> optional = svgRenderTemplateRepository.findById(id);
        RenderingTemplate svgRenderTemplate = optional.orElseThrow(() -> new TemplateException(ErrorConstants.INVALID_TEMPLATE_ID));

        return svgRenderTemplate;

    }
}

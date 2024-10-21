/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.entity.SvgTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.repository.SvgTemplateRepository;
import io.mosip.certify.core.spi.SvgTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class SvgTemplateServiceImpl implements SvgTemplateService {
    @Autowired
    SvgTemplateRepository svgRenderTemplateRepository;


    @Override
    public SvgTemplate getSvgTemplate(UUID id) {
        Optional<SvgTemplate> optional = svgRenderTemplateRepository.findById(id);
        SvgTemplate svgRenderTemplate = optional.orElseThrow(() -> new TemplateException(ErrorConstants.INVALID_TEMPLATE_ID));

        return svgRenderTemplate;

    }
}

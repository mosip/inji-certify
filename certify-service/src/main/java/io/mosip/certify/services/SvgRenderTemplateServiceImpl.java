/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
import io.mosip.certify.core.spi.SvgRenderTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class SvgRenderTemplateServiceImpl implements SvgRenderTemplateService {
    @Autowired
    SvgRenderTemplateRepository svgRenderTemplateRepository;


    @Override
    public SvgRenderTemplate getSvgTemplate(UUID id) {
        Optional<SvgRenderTemplate> optional = svgRenderTemplateRepository.findById(id);
        SvgRenderTemplate svgRenderTemplate = optional.orElseThrow(() -> new CertifyException(ErrorConstants.INVALID_TEMPLATE_ID));

        return svgRenderTemplate;

    }
}

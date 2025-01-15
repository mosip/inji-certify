/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import io.mosip.certify.api.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.entity.RenderingTemplate;
import io.mosip.certify.repository.RenderingTemplateRepository;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class RenderingTemplateServiceImpl implements RenderingTemplateService {
    @Autowired
    RenderingTemplateRepository renderTemplateRepository;

    //TODO: Cache it...

    @Override
    @Cacheable(cacheNames="renderTemplate", key="#id")
    public RenderingTemplateDTO getTemplate(String id) {
        Optional<RenderingTemplate> optional = renderTemplateRepository.findById(id);
        RenderingTemplate renderingTemplate = optional.orElseThrow(() -> new RenderingTemplateException(ErrorConstants.INVALID_TEMPLATE_ID));
        RenderingTemplateDTO renderingTemplateDTO = new RenderingTemplateDTO();
        renderingTemplateDTO.setId(renderingTemplate.getId());
        renderingTemplateDTO.setTemplate(renderingTemplate.getTemplate());
        renderingTemplateDTO.setCreatedTimes(renderingTemplate.getCreatedtimes());
        renderingTemplateDTO.setUpdatedTimes(renderingTemplate.getUpdatedtimes());

        return renderingTemplateDTO;
    }
}

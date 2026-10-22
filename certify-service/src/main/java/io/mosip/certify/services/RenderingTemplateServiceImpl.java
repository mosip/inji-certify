package io.mosip.certify.services;

import java.util.Optional;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import io.mosip.certify.core.dto.RenderingTemplateDTO;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import io.mosip.certify.entity.RenderingTemplate;
import io.mosip.certify.repository.RenderingTemplateRepository;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class RenderingTemplateServiceImpl implements RenderingTemplateService {
    private final RenderingTemplateRepository renderTemplateRepository;

    public RenderingTemplateServiceImpl(RenderingTemplateRepository renderTemplateRepository) {
        this.renderTemplateRepository = renderTemplateRepository;
    }

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

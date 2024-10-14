package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.SvgRenderTemplateDto;
import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
import io.mosip.certify.core.spi.SvgRenderTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Component
public class SvgRenderTemplateServiceImpl implements SvgRenderTemplateService {
    @Autowired
    SvgRenderTemplateRepository svgRenderTemplateRepository;


    @Override
    public SvgRenderTemplateDto getSvgTemplate(String id) {
        Optional<SvgRenderTemplate> optional = svgRenderTemplateRepository.findById(id);
        SvgRenderTemplate svgRenderTemplate = optional.orElseThrow(() -> new CertifyException(ErrorConstants.INVALID_TEMPLATE_ID));

        SvgRenderTemplateDto svgRenderTemplateDto = new SvgRenderTemplateDto();
        svgRenderTemplateDto.setId(svgRenderTemplate.getId());
        svgRenderTemplateDto.setSvgTemplate(svgRenderTemplate.getSvgTemplate());
        svgRenderTemplateDto.setLastModified(svgRenderTemplate.getLastModified());

        return svgRenderTemplateDto;

    }
}

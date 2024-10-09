package io.mosip.certify.services;

import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
import io.mosip.certify.core.spi.SvgRenderTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
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
    public SvgRenderTemplate getSvgTemplate(UUID id) {
        Optional<SvgRenderTemplate> optional = svgRenderTemplateRepository.findById(id);
        SvgRenderTemplate svgRenderTemplate = optional.orElseThrow(() -> new CertifyException("No template found against provided id."));

        if(svgRenderTemplate.getSvgTemplate().isEmpty()) {
            throw  new CertifyException("Empty template found.");
        }

        return svgRenderTemplate;

    }
}

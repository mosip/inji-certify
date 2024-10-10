package io.mosip.certify.config;

import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;


@Component
@Slf4j
public class TemplateConfig  implements CommandLineRunner {
    @Autowired
    SvgRenderTemplateRepository svgRenderTemplateRepository;

    @Value("#{${mosip.certify.svg-templates}}")
    private LinkedHashMap<String, Object> svgTemplateMap;

    @Override
    public void run(String... args) throws Exception {
        List<SvgRenderTemplate> svgRenderTemplateList = svgRenderTemplateRepository.findAll();

        if(svgRenderTemplateList.isEmpty()) {
            svgTemplateMap.forEach((key, value) -> {
                SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
                svgRenderTemplate.setId(UUID.randomUUID());
                svgRenderTemplate.setSvgTemplate(value.toString());
                log.info("Template inserted in svg template table at: " + LocalDateTime.now());
                svgRenderTemplate.setLastModified(LocalDateTime.now());
                svgRenderTemplateRepository.save(svgRenderTemplate);
            });
        }

        log.info("=============== CERTIFY TEMPLATE SETUP COMPLETED ===============");
    }
}

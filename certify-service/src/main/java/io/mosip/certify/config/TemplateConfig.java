/* This is for temporary purpose till an API isn’t added to simplify Issuer onboarding. */

package io.mosip.certify.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.repository.SvgRenderTemplateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;


@Component
@Slf4j
public class TemplateConfig  implements CommandLineRunner {
    @Autowired
    SvgRenderTemplateRepository svgRenderTemplateRepository;

    @Value("${mosip.certify.svg-templates}")
    private String svgTemplateJson;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Override
    public void run(String... args) throws Exception {
        String svgTemplateContent;
        LinkedHashMap<String, Object> svgTemplateMap;
        Resource resource = new ClassPathResource(svgTemplateJson);
        try {
            svgTemplateContent = (Files.readString(resource.getFile().toPath()));
        } catch (IOException e) {
            throw new FileNotFoundException("Missing local json file for referring svg templates " + e.getMessage());
        }

        try {
            svgTemplateMap = objectMapper.readValue(svgTemplateContent, LinkedHashMap.class);
        } catch (JsonProcessingException e) {
            throw new CertifyException("Missing configuration for svg template content " + e.getMessage());
        }

         svgTemplateMap.forEach((key, value) -> {
            SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
            svgRenderTemplate.setId(key);
            if(domainUrl.startsWith("http")) {
                svgRenderTemplate.setSvgTemplate(value.toString());
            } else {
                String svgTemplate = restTemplate.getForObject(value.toString(), String.class);
                svgRenderTemplate.setSvgTemplate(svgTemplate);
            }
            svgRenderTemplate.setLastModified(LocalDateTime.now());
            log.info("Template inserted in svg template table.");
            svgRenderTemplateRepository.save(svgRenderTemplate);
        });

        log.info("=============== CERTIFY TEMPLATE SETUP COMPLETED ===============");
    }
}

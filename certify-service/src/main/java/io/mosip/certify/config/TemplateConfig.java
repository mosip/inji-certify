/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;


@Configuration
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

    @Override
    public void run(String... args) throws Exception {
        String svgTemplateContent = "";
        LinkedHashMap<String, Object> svgTemplateMap;
        if(svgTemplateJson.startsWith("https")) {
            svgTemplateContent = restTemplate.getForObject(svgTemplateContent, String.class);
        } else {
            Resource resource = new ClassPathResource(svgTemplateJson);
            try {
                svgTemplateContent = (Files.readString(resource.getFile().toPath()));
            } catch (IOException e) {
                log.error("Missing local json file for referring svg templates", e);
            }
        }

        List<SvgRenderTemplate> svgRenderTemplates = svgRenderTemplateRepository.findAll();
        if(svgRenderTemplates.isEmpty()) {
            SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
            UUID id = UUID.fromString(svgTemplateJson);
            svgRenderTemplate.setId(id);
            svgRenderTemplate.setSvgTemplate(svgTemplateContent);
            LocalDateTime localDateTime = LocalDateTime.now();
            svgRenderTemplate.setCreatedtimes(localDateTime);
            svgRenderTemplate.setUpdatedtimes(localDateTime);
            log.info("Template inserted in svg template table.");
            svgRenderTemplateRepository.save(svgRenderTemplate);
        }


//        if(!svgTemplateContent.isEmpty()) {
//            try {
//                svgTemplateMap = objectMapper.readValue(svgTemplateContent, LinkedHashMap.class);
//            } catch (JsonProcessingException e) {
//                throw new CertifyException("Missing configuration for svg template content " + e.getMessage());
//            }
//
//            List<SvgRenderTemplate> svgRenderTemplates = svgRenderTemplateRepository.findAll();
//
//            if(svgRenderTemplates.isEmpty()) {
//                svgTemplateMap.forEach((key, value) -> {
//                    LinkedHashMap<String, Object> templateObject = ((LinkedHashMap<String, Object>)  value);
//                    SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
//                    UUID id = UUID.fromString(templateObject.get("id").toString());
//                    String content = templateObject.get("content").toString();
//                    svgRenderTemplate.setId(id);
//                    if(content.startsWith("https")) {
//                        String svgTemplate = restTemplate.getForObject(content, String.class);
//                        svgRenderTemplate.setSvgTemplate(svgTemplate);
//                    } else {
//                        svgRenderTemplate.setSvgTemplate(content);
//                    }
//                    svgRenderTemplate.setTemplateName(key);
//                    LocalDateTime localDateTime = LocalDateTime.now();
//                    svgRenderTemplate.setCreatedtimes(localDateTime);
//                    svgRenderTemplate.setUpdatedtimes(localDateTime);
//                    log.info("Template inserted in svg template table.");
//                    svgRenderTemplateRepository.save(svgRenderTemplate);
//                });
//            }
//        }


        log.info("=============== CERTIFY TEMPLATE SETUP COMPLETED ===============");
    }
}

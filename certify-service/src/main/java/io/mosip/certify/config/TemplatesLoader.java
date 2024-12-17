/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* This is for temporary purpose till an API isn’t added to simplify Issuer onboarding. */

package io.mosip.certify.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.services.entity.RenderingTemplate;
import io.mosip.certify.services.repository.RenderingTemplateRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.*;


@Configuration
@Slf4j
public class TemplatesLoader implements CommandLineRunner {
    @Autowired
    RenderingTemplateRepository svgRenderTemplateRepository;

    @Value("${mosip.certify.rendering-templates:}")
    private String svgTemplateJson;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Override
    public void run(String... args) throws Exception {
        Long count = svgRenderTemplateRepository.count();
        if (count != 0) {
            return;
        }
        String svgTemplateContent = "";

        if(svgTemplateJson.startsWith("http")) {
            svgTemplateContent = restTemplate.getForObject(svgTemplateJson, String.class);
        } else {
            Resource resource = new ClassPathResource(svgTemplateJson);
            // TODO: Verify this w.r.t local path
            try {
                svgTemplateContent = (Files.readString(resource.getFile().toPath()));
            } catch (IOException e) {
                log.error("Missing local json file for referring svg templates", e);
            }
        }

        if(!svgTemplateContent.isEmpty()) {
            try {
                List <Object> svgTemplateMap = objectMapper.readValue(svgTemplateContent, List.class);
                svgTemplateMap.forEach((value) -> {
                    RenderingTemplate svgRenderTemplate = new RenderingTemplate();
                    LinkedHashMap<String, Object> valueMap = (LinkedHashMap<String, Object>) value;
                    String id = valueMap.get("id").toString();
                    svgRenderTemplate.setId(id);
                    String templateURI = valueMap.get("content").toString();
                    if(templateURI.startsWith("http")) {
                        String templateFromUrl = restTemplate.getForObject(templateURI, String.class);
                        svgRenderTemplate.setTemplate(templateFromUrl);
                    } else {
                        svgRenderTemplate.setTemplate(templateURI);
                    }
                    LocalDateTime localDateTime = LocalDateTime.now();
                    svgRenderTemplate.setCreatedtimes(localDateTime);
                    svgRenderTemplate.setUpdatedtimes(localDateTime);
                    log.info("Template inserted in svg template table.");
                    svgRenderTemplateRepository.save(svgRenderTemplate);
                });
            } catch (JsonProcessingException e) {
                log.error("Missing configuration for svg template content " + e.getMessage());
            }

        }
        log.info("=============== CERTIFY TEMPLATE SETUP COMPLETED ===============");
    }
}

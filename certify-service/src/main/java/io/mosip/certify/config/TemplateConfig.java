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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;


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
            throw new FileNotFoundException("missing local svg template data file " + e.getMessage());
        }

        try {
            svgTemplateMap = objectMapper.readValue(svgTemplateContent, LinkedHashMap.class);
        } catch (JsonProcessingException e) {
            throw new CertifyException("Missing well known config");
        }

        List<SvgRenderTemplate> svgRenderTemplateList = svgRenderTemplateRepository.findAll();

        if(svgRenderTemplateList.isEmpty()) {
            svgTemplateMap.forEach((key, value) -> {
                SvgRenderTemplate svgRenderTemplate = new SvgRenderTemplate();
                svgRenderTemplate.setId(UUID.randomUUID());
                if(domainUrl.startsWith("https")) {
                    String svgTemplate = restTemplate.getForObject(value.toString(), String.class);
                    svgRenderTemplate.setSvgTemplate(svgTemplate);
                } else {
                    svgRenderTemplate.setSvgTemplate(value.toString());
                }
                svgRenderTemplate.setLastModified(LocalDateTime.now());
                log.info("Template inserted in svg template table.");
                svgRenderTemplateRepository.save(svgRenderTemplate);
            });
        }

        log.info("=============== CERTIFY TEMPLATE SETUP COMPLETED ===============");
    }
}

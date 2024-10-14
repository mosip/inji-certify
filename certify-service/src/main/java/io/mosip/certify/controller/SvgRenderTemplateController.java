package io.mosip.certify.controller;

import io.mosip.certify.core.entity.SvgRenderTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.SvgRenderTemplateService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/public")
public class SvgRenderTemplateController {
    @Autowired
    SvgRenderTemplateService svgRenderTemplateService;

    @GetMapping("/svg-template/{id}")
    public ResponseEntity<String> serveSvgTemplate(@PathVariable String id) throws CertifyException {
        SvgRenderTemplate template = svgRenderTemplateService.getSvgTemplate(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "image/svg")
                .cacheControl(CacheControl.maxAge(1, TimeUnit.DAYS).cachePublic())
                .lastModified(template.getLastModified().atZone(ZoneId.systemDefault()).toInstant())
                .body(template.getSvgTemplate());
    }
}

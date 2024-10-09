package io.mosip.certify.controller;

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

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/public")
public class SvgRenderTemplateController {
    private final String svgTemplate = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"200\" height=\"200\">" +
            "<rect width=\"200\" height=\"200\" fill=\"#ff6347\"/>" +
            "<text x=\"100\" y=\"100\" font-size=\"30\" text-anchor=\"middle\" fill=\"white\">" +
            "Hello, SVG!" +
            "</text></svg>";

    @Autowired
    SvgRenderTemplateService svgRenderTemplateService;

    @GetMapping("/svg-template/{id}")
    public ResponseEntity<String> serverSvgTemplate(@PathVariable UUID id) throws CertifyException {
        String template = svgRenderTemplateService.getSvgTemplate(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "image/svg")
                .cacheControl(CacheControl.maxAge(1, TimeUnit.DAYS).cachePublic())
                .body(template);
    }
}

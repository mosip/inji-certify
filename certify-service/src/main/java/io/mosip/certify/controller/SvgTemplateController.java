/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.entity.SvgTemplate;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.TemplateException;
import io.mosip.certify.core.spi.SvgTemplateService;
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
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/public")
public class SvgTemplateController {
    @Autowired
    SvgTemplateService svgTemplateService;

    @GetMapping("/svg-template/{id}")
    public ResponseEntity<String> serveSvgTemplate(@PathVariable UUID id) throws TemplateException {
        SvgTemplate template = svgTemplateService.getSvgTemplate(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "image/svg+xml")
                .cacheControl(CacheControl.maxAge(1, TimeUnit.DAYS).cachePublic())
                .lastModified(template.getUpdatedtimes().atZone(ZoneId.systemDefault()).toInstant())
                .body(template.getTemplate());
    }
}

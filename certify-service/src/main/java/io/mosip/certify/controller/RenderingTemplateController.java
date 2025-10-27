/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import java.time.ZoneId;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.certify.core.dto.RenderingTemplateDTO;
import io.mosip.certify.core.exception.RenderingTemplateException;
import io.mosip.certify.core.spi.RenderingTemplateService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/rendering-template")
public class RenderingTemplateController {
    @Value("${mosip.certify.rendering-template.cache-max-age-days:1}")
    Integer maxAgeDays;
    @Autowired
    RenderingTemplateService renderingTemplateService;

    @GetMapping("/{id}")
    public ResponseEntity<String> serveSvgTemplate(@PathVariable String id) throws RenderingTemplateException {
        RenderingTemplateDTO template = renderingTemplateService.getTemplate(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "image/svg+xml")
                .cacheControl(CacheControl.maxAge(maxAgeDays, TimeUnit.DAYS).cachePublic())
                .lastModified(template.getUpdatedTimes().atZone(ZoneId.systemDefault()).toInstant())
                .body(template.getTemplate());
    }
}

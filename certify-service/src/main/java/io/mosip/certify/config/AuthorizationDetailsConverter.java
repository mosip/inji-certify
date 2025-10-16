/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.AuthorizationDetail;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Spring Converter to parse authorization_details from JSON string to List<AuthorizationDetail>
 * This is needed to handle form-urlencoded requests where authorization_details comes as a JSON string
 */
@Slf4j
@Component
public class AuthorizationDetailsConverter implements Converter<String, List<AuthorizationDetail>> {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public List<AuthorizationDetail> convert(String source) {
        if (source == null || source.trim().isEmpty()) {
            return null;
        }

        try {
            log.debug("Converting authorization_details from string: {}", source);
            List<AuthorizationDetail> result = objectMapper.readValue(
                source,
                new TypeReference<List<AuthorizationDetail>>() {}
            );
            log.debug("Successfully converted authorization_details, size: {}", result != null ? result.size() : 0);
            return result;
        } catch (Exception e) {
            log.error("Failed to parse authorization_details from string: {}", source, e);
            throw new IllegalArgumentException("Invalid authorization_details format: " + e.getMessage(), e);
        }
    }
}


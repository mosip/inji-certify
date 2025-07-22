/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.*;
import java.util.stream.Collectors;

import io.mosip.certify.utils.MDocUtils;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.core.constants.MDocConstants;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.kernel.signature.service.SignatureService;
import lombok.extern.slf4j.Slf4j;

/**
 * MDocCredential implementation for ISO 18013-5 compliant mobile documents
 * Handles mDoc structure creation, namespace processing, and COSE signing
 */
@Slf4j
@Component
public class MDocCredential extends Credential {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public MDocCredential(VCFormatter vcFormatter, SignatureService signatureService) {
        super(vcFormatter, signatureService);
    }

    @Override
    public boolean canHandle(String format) {
        return MDocConstants.MSO_MDOC_FORMAT.equals(format);
    }

    @Override
    public String createCredential(Map<String, Object> templateParams, String templateName) {
        try {
            String templatedJSON = super.createCredential(templateParams, templateName);
            log.info("Templated JSON: {}", templatedJSON);

            Map<String, Object> finalMDoc = MDocUtils.processTemplatedJson(templatedJSON, templateParams);

            // Convert to JSON and return
            String result = objectMapper.writeValueAsString(finalMDoc);
            log.info("Final mDoc credential created: {}", result);
            return result;

        } catch (Exception e) {
            log.error("Error creating mDoc credential: {}", e.getMessage(), e);
            return "";
        }
    }

    @Override
    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm,
                                String appID, String refID, String publicKeyURL) {
//        TODO: To Implement Later
        VCResult<String> result = new VCResult<>();
        return result;
    }

    private Object convertJsonNode(JsonNode node) {
        if (node.isTextual()) return node.asText();
        if (node.isInt()) return node.asInt();
        if (node.isLong()) return node.asLong();
        if (node.isDouble()) return node.asDouble();
        if (node.isBoolean()) return node.asBoolean();
        if (node.isArray()) {
            List<Object> list = new ArrayList<>();
            node.elements().forEachRemaining(element -> list.add(convertJsonNode(element)));
            return list;
        }
        if (node.isObject()) {
            Map<String, Object> map = new HashMap<>();
            node.fields().forEachRemaining(field -> map.put(field.getKey(), convertJsonNode(field.getValue())));
            return map;
        }
        return node.asText(); // fallback
    }
}
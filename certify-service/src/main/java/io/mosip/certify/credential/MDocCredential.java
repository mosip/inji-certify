/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package io.mosip.certify.credential;

import java.util.*;
import java.util.stream.Collectors;

import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.utils.MDocUtils;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private ObjectMapper objectMapper;

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
            throw new CertifyException("MDOC_CREATION_FAILED", "Failed to create mDoc credential", e);
        }
    }

//    @Override
//    public VCResult<?> addProof(String vcToSign, String headers, String signAlgorithm,
//                                String appID, String refID, String publicKeyURL) {
//        TODO: To Implement Later
        VCResult<String> result = new VCResult<>();
//
//        try {
//            byte[] cborBytes = Base64.getDecoder().decode(vcToSign);
//            Map<String, Object> mDocData = CBORUtils.decodeToMap(cborBytes);
//
//            @SuppressWarnings("unchecked")
//            Map<String, Object> issuerSignedData = (Map<String, Object>) mDocData.get(MDocConstants.ISSUER_SIGNED);
//
//            if (issuerSignedData == null) {
//                log.error("No issuer signed data found in mDoc");
//                result.setCredential(vcToSign);
//                return result;
//            }
//
//            // Create MSO with value digests
//            MobileSecurityObject mso = new MobileSecurityObject();
//            mso.setVersion("1.0");
//            mso.setDigestAlgorithm(MDocConstants.DIGEST_ALGORITHM_SHA256);
//            mso.setDocType((String) mDocData.get(MDocConstants.DOC_TYPE));
//
//            // Create value digests
//            Map<String, Map<String, byte[]>> valueDigests = new HashMap<>();
//            @SuppressWarnings("unchecked")
//            Map<String, Object> namespaces = (Map<String, Object>) issuerSignedData.get(MDocConstants.NAMESPACES);
//
//            if (namespaces != null) {
//                for (Map.Entry<String, Object> namespaceEntry : namespaces.entrySet()) {
//                    String namespace = namespaceEntry.getKey();
//                    @SuppressWarnings("unchecked")
//                    List<List<Object>> items = (List<List<Object>>) namespaceEntry.getValue();
//
//                    Map<String, byte[]> namespaceDigests = new HashMap<>();
//                    for (List<Object> item : items) {
//                        if (item.size() >= 4) {
//                            Integer digestID = (Integer) item.get(0);
//                            try {
//                                byte[] itemBytes = CBORUtils.encode(item);
//                                byte[] digest = DigestUtils.calculateSHA256(itemBytes);
//                                namespaceDigests.put(String.valueOf(digestID), digest);
//                            } catch (CertifyException e) {
//                                log.error("Error calculating digest for item {}: {}", digestID, e.getMessage());
//                            }
//                        }
//                    }
//                    valueDigests.put(namespace, namespaceDigests);
//                }
//            }
//
//            // Sign the MSO using COSE (placeholder implementation)
//            // TODO: Implement actual COSE signing
//            String signedMSO = "coseSigningService.signMSO(mso, signAlgorithm, appID, refID, publicKeyURL)";
//
//            // Update mDoc with signed MSO
//            mDocData.put(MDocConstants.ISSUER_AUTH, signedMSO);
//
//            // Re-encode to CBOR
//            byte[] signedCborBytes = CBORUtils.encode(mDocData);
//            result.setCredential(Base64.getEncoder().encodeToString(signedCborBytes));
//            result.setFormat(MDocConstants.MSO_MDOC_FORMAT);
//
//        } catch (Exception e) {
//            log.error("Error adding proof to mDoc: {}", e.getMessage(), e);
//            result.setCredential(vcToSign);
//        }
//
//        return result;
//    }

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
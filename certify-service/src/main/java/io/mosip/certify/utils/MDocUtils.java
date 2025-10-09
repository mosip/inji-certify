/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;

import java.io.ByteArrayOutputStream;

import io.mosip.certify.config.MDocConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.VCDM2Constants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.signature.dto.CoseSignRequestDto;
import io.mosip.kernel.signature.service.CoseSignatureService;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Utility class for mDoc (Mobile Document) specific operations.
 * Provides helper methods for mDoc structure creation and manipulation.
 */
@Slf4j
@Component
public class MDocUtils {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MDocConfig mDocConfig;

    /**
     * Process templated JSON to create final mDoc structure
     */
    public Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            if (templateNode.has("validityInfo")) {
                JsonNode validityInfo = templateNode.get("validityInfo");
                Map<String, Object> validity = objectMapper.convertValue(validityInfo, Map.class);

                if (validity.containsKey(VCDM2Constants.VALID_FROM)) {
                    String validFromValue = (String) validity.get(VCDM2Constants.VALID_FROM);
                    if ("${_validFrom}".equals(validFromValue)) {
                        String currentTime = ZonedDateTime.now(ZoneOffset.UTC)
                                .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
                        validity.put(VCDM2Constants.VALID_FROM, currentTime);
                    }
                }
                if (validity.containsKey(VCDM2Constants.VALID_UNITL)) {
                    String validUntilValue = (String) validity.get(VCDM2Constants.VALID_UNITL);
                    if ("${_validUntil}".equals(validUntilValue)) {
                        String futureTime = ZonedDateTime.now(ZoneOffset.UTC)
                                .plusYears(mDocConfig.getValidityPeriodYears())
                                .format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
                        validity.put(VCDM2Constants.VALID_UNITL, futureTime);
                    }
                }


                finalMDoc.put("validityInfo", validity);
            }

            if (templateParams.containsKey("didUrl")) {
                finalMDoc.put("_issuer", templateParams.get("didUrl"));
            }
            if (templateParams.containsKey("_holderId")) {
                finalMDoc.put("_holderId", templateParams.get("_holderId"));
            }
            if (templateNode.has("docType")) {
                finalMDoc.put("_docType", templateNode.get("docType").asText());
            }

            // Process namespaces
            Map<String, Object> nameSpaces = new HashMap<>();

            if (templateNode.has("nameSpaces")) {
                JsonNode nameSpacesNode = templateNode.get("nameSpaces");
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                    List<Map<String, Object>> processedItems = processNamespaceItems(namespaceItems);
                    nameSpaces.put(namespaceName, processedItems);
                });
            }
            finalMDoc.put("nameSpaces", nameSpaces);

            return finalMDoc;

        } catch (Exception e) {
            log.error("Error processing templated JSON: {}", e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Process items within a namespace
     */
    public List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems) {
        List<Map<String, Object>> processedItems = new ArrayList<>();

        // First, add all items from template
        for (JsonNode item : namespaceItems) {
            Map<String, Object> itemMap = new HashMap<>();
            itemMap.put("digestID", item.get("digestID").asInt());
            itemMap.put("elementIdentifier", item.get("elementIdentifier").asText());

            // Handle elementValue which could be string or complex object
            JsonNode elementValue = item.get("elementValue");
            if (elementValue.isTextual()) {
                itemMap.put("elementValue", elementValue.asText());
            } else {
                // Convert complex objects (like driving_privileges)
                Object value = objectMapper.convertValue(elementValue, Object.class);
                itemMap.put("elementValue", value);
            }

            processedItems.add(itemMap);
        }

        return processedItems;
    }

    /**
     * Adds random salts to each data element
     */
    public static Map<String, Object> addRandomSalts(Map<String, Object> mDocJson) {
        Map<String, Object> nameSpaces = (Map<String, Object>) mDocJson.get("nameSpaces");
        Map<String, Object> saltedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : nameSpaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<Map<String, Object>> saltedElements = new ArrayList<>();

            for (Map<String, Object> element : elements) {
                // Generate 24-byte random salt
                byte[] randomSalt = new byte[24];
                new SecureRandom().nextBytes(randomSalt);

                // Clone element with random salt as hex string
                Map<String, Object> saltedElement = new HashMap<>(element);
                saltedElement.put("random", randomSalt);

                saltedElements.add(saltedElement);
            }

            saltedNamespaces.put(namespaceName, saltedElements);
        }

        return saltedNamespaces;
    }

    /**
     * Calculates SHA-256 digests for salted elements
     */
    public static Map<String, Object> calculateDigests(Map<String, Object> saltedNamespaces, Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> taggedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : saltedNamespaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<byte[]> taggedElements = new ArrayList<>();
            Map<Integer, byte[]> digestMap = new HashMap<>();

            for (Map<String, Object> element : elements) {
                // Encode to CBOR and wrap with Tag 24 in one step
                byte[] taggedCbor = wrapWithCBORTag24(element);
                taggedElements.add(taggedCbor);

                // Calculate digest of the Tag 24 wrapped CBOR
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(taggedCbor);
                digestMap.put((Integer) element.get("digestID"), digest);
            }

            taggedNamespaces.put(namespaceName, taggedElements);
            namespaceDigests.put(namespaceName, digestMap);
        }

        return taggedNamespaces;
    }

    public static byte[] encodeToCBOR(Object obj) throws Exception {
        try {
            Object preprocessedData = preprocessForCBOR(obj);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);
            encoder.encode(convertToDataItem(preprocessedData));
            return baos.toByteArray();
        } catch (Exception e) {
            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
        }
    }

    /**
     * Preprocesses objects for CBOR encoding (handles dates, byte arrays, etc.)
     */
    public static Object preprocessForCBOR(Object obj) {
        if (obj == null) {
            return null;
        }

        // Handle byte arrays directly - don't convert to hex
        if (obj instanceof byte[]) {
            return obj;
        }

        if (obj instanceof String) {
            String str = (String) obj;
            if (isDateOnlyString(str)) {
                return createCBORTaggedDate(str);
            }
            return str;
        }

        if (obj instanceof Map) {
            Map<Object, Object> map = (Map<Object, Object>) obj;
            Map<Object, Object> processedMap = new HashMap<>();

            for (Map.Entry<Object, Object> entry : map.entrySet()) {
                Object processedKey = preprocessForCBOR(entry.getKey());
                Object processedValue = preprocessForCBOR(entry.getValue());
                processedMap.put(processedKey, processedValue);
            }
            return processedMap;
        }

        if (obj instanceof List) {
            List<Object> list = (List<Object>) obj;
            List<Object> processedList = new ArrayList<>();
            for (Object item : list) {
                processedList.add(preprocessForCBOR(item));
            }
            return processedList;
        }

        return obj; // Return as-is for primitives
    }

    private static DataItem convertToDataItem(Object obj) {
        if (obj == null) {
            return SimpleValue.NULL;
        }
        if (obj instanceof String) {
            return new UnicodeString((String) obj);
        }
        if (obj instanceof Integer) {
            int value = (Integer) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof Long) {
            long value = (Long) obj;
            if (value < 0) {
                return new NegativeInteger(value);
            } else {
                return new UnsignedInteger(value);
            }
        }
        if (obj instanceof Boolean) {
            return (Boolean) obj ? SimpleValue.TRUE : SimpleValue.FALSE;
        }
        if (obj instanceof Double) {
            return new DoublePrecisionFloat((Double) obj);
        }
        if (obj instanceof Float) {
            return new SinglePrecisionFloat((Float) obj);
        }
        if (obj instanceof byte[]) {
            return new ByteString((byte[]) obj);
        }
        if (obj instanceof java.util.Map) {
            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            for (Object entry : ((java.util.Map<?, ?>) obj).entrySet()) {
                java.util.Map.Entry<?, ?> mapEntry = (java.util.Map.Entry<?, ?>) entry;
                DataItem keyItem = convertToDataItem(mapEntry.getKey());
                DataItem valueItem = convertToDataItem(mapEntry.getValue());
                map.put(keyItem, valueItem);
            }
            return map;
        }
        if (obj instanceof List) {
            Array array = new Array();
            for (Object item : (List<?>) obj) {
                array.add(convertToDataItem(item));
            }
            return array;
        }
        // Handle tagged objects (for CBOR tags like date)
        if (obj instanceof java.util.Map && ((java.util.Map<?, ?>) obj).containsKey("__cbor_tag")) {
            java.util.Map<?, ?> taggedMap = (java.util.Map<?, ?>) obj;
            int tag = (Integer) taggedMap.get("__cbor_tag");
            Object value = taggedMap.get("__cbor_value");
            DataItem dataItem = convertToDataItem(value);
            dataItem.setTag(tag);
            return dataItem;
        }
        // For any other type, convert to string
        return new UnicodeString(obj.toString());
    }


    /**
     * Checks if a string represents a date-only value (YYYY-MM-DD)
     */
    public static boolean isDateOnlyString(String str) {
        try {
            LocalDate.parse(str, DateTimeFormatter.ISO_LOCAL_DATE);
            return str.matches("\\d{4}-\\d{2}-\\d{2}");
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /**
     * Creates a CBOR tagged date (tag 1004) for date-only strings
     */
    public static Map<String, Object> createCBORTaggedDate(String dateStr) {
        Map<String, Object> taggedDate = new HashMap<>();
        taggedDate.put("__cbor_tag", 1004);
        taggedDate.put("__cbor_value", dateStr);
        return taggedDate;
    }

    /**
     * Converts hex string to byte array
     */
    public static byte[] hexStringToByteArray(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4) + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Creates the Mobile Security Object (MSO) structure
     */
    public Map<String, Object> createMobileSecurityObject(Map<String, Object> mDocJson, Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", mDocConfig.getMsoVersion());
        mso.put("digestAlgorithm", mDocConfig.getDigestAlgorithm());

        // Create valueDigests structure
        Map<String, Object> nameSpacesDigests = new HashMap<>();
        nameSpacesDigests.putAll(namespaceDigests);
        Map<String, Object> valueDigests = new HashMap<>();
        valueDigests.put("nameSpaces", nameSpacesDigests);

        mso.put("valueDigests", valueDigests);
        mso.put("docType", mDocJson.get("_docType"));

        // Create validity info with current timestamp
        Map<String, Object> validityInfo = new HashMap<>();

        if (mDocJson.containsKey("validityInfo")) {
            Map<String, Object> originalValidity = (Map<String, Object>) mDocJson.get("validityInfo");
            validityInfo.put(VCDM2Constants.VALID_FROM, originalValidity.get(VCDM2Constants.VALID_FROM));
            validityInfo.put(VCDM2Constants.VALID_UNITL, originalValidity.get(VCDM2Constants.VALID_UNITL));
        }
        mso.put("validityInfo", validityInfo);

        // Add device key info (placeholder - should be from wallet's PoP)
        Map<String, Object> deviceKeyInfo = createDeviceKeyInfo(mDocJson.get("_holderId"));
        mso.put("deviceKeyInfo", deviceKeyInfo);

        return mso;
    }

    /**
     * Creates device key info structure (placeholder implementation)
     */
    public static Map<String, Object> createDeviceKeyInfo(Object deviceInfo) throws Exception {
        String deviceKeyEncoded = deviceInfo.toString();
        if (deviceKeyEncoded.startsWith("did:jwk:")) {
            deviceKeyEncoded = deviceKeyEncoded.substring("did:jwk:".length());
        }

        byte[] decodedBytes = Base64.getUrlDecoder().decode(deviceKeyEncoded);
        String decodedJson = new String(decodedBytes);

        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> jwk = mapper.readValue(decodedJson, Map.class);

        Map<Object, Object> coseKey = new HashMap<>();
        coseKey.put(1, 2);  // kty: EC2
        coseKey.put(3, -7); // alg: ES256 (ECDSA with SHA-256)

        if (jwk.containsKey("kid")) {
            // Pass through the key ID if it exists in the source JWK
            coseKey.put(2, ((String) jwk.get("kid")).getBytes());
        }
        // Map curve
        String crv = (String) jwk.get("crv");
        switch (crv) {
            case "P-256" -> coseKey.put(-1, 1);
            case "P-384" -> coseKey.put(-1, 2);
            case "P-521" -> coseKey.put(-1, 3);
            case null, default -> throw new IllegalArgumentException("Unsupported curve for EC2 key type: " + crv);
        }

        coseKey.put(-2, Base64.getUrlDecoder().decode((String) jwk.get("x")));
        if (jwk.containsKey("y")) {
            coseKey.put(-3, Base64.getUrlDecoder().decode((String) jwk.get("y")));
        }

        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", coseKey);
        return deviceKeyInfo;
    }

    /**
     * Signs the MSO using COSE_Sign1 structure
     */
    public static byte[] signMSO(Map<String, Object> mso, String appID, String refID, String signAlgorithm, DIDDocumentUtil didDocumentUtil, CoseSignatureService coseSignatureService) throws Exception {

        try {
            byte[] msoCbor = encodeToCBOR(mso);

            CoseSignRequestDto signRequest = new CoseSignRequestDto();

            String base64UrlPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(msoCbor);

            signRequest.setPayload(base64UrlPayload);
            signRequest.setApplicationId(appID);
            signRequest.setReferenceId(refID);
            signRequest.setAlgorithm(signAlgorithm);

            Map<String, Object> protectedHeader = new HashMap<>();
            protectedHeader.put("x5c", true);
            signRequest.setProtectedHeader(protectedHeader);

            String hexSignedData = coseSignatureService.coseSign1(signRequest).getSignedData();
            return hexStringToByteArray(hexSignedData);

        } catch (CertifyException e) {
            log.error("Error during COSE signing: {}", e.getMessage(), e);
            throw new CertifyException("COSE signing failed: " + e.getMessage());
        }
    }


    public static byte[] wrapWithCBORTag24(Map<String, Object> element) throws IOException {
        try {
            // First encode the element to CBOR
            ByteArrayOutputStream innerBaos = new ByteArrayOutputStream();
            CborEncoder innerEncoder = new CborEncoder(innerBaos);
            innerEncoder.encode(convertToDataItem(element));
            byte[] elementCbor = innerBaos.toByteArray();

            // Then wrap that byte string in Tag 24
            ByteArrayOutputStream outerBaos = new ByteArrayOutputStream();
            CborEncoder outerEncoder = new CborEncoder(outerBaos);
            ByteString wrappedBytes = new ByteString(elementCbor);
            wrappedBytes.setTag(24);
            outerEncoder.encode(wrappedBytes);

            return outerBaos.toByteArray();
        } catch (CborException e) {
            throw new IOException("Failed to wrap with CBOR tag 24", e);
        }
    }

    /**
     * Creates the final IssuerSigned structure combining namespaces and issuerAuth
     */
    public static Map<String, Object> createIssuerSignedStructure(Map<String, Object> processedNamespaces, byte[] signedMSO) {
        return Map.of(
                "nameSpaces", processedNamespaces,
                "issuerAuth", signedMSO
        );
    }
}
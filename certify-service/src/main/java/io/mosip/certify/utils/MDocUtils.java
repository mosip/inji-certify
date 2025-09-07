/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.*;
import java.io.ByteArrayOutputStream;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CertificateResponseDTO;
import io.mosip.kernel.signature.service.SignatureServicev2;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.LocalDateTime;
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

import javax.xml.bind.DatatypeConverter;

/**
 * Utility class for mDoc (Mobile Document) specific operations.
 * Provides helper methods for mDoc structure creation and manipulation.
 */
@Slf4j
public class MDocUtils {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Calculate the minimum excludant (mex) for a set of integers
     */
    public static int calculateMex(Set<Integer> numbers) {
        int mex = 0;
        while (numbers.contains(mex)) {
            mex++;
        }
        return mex;
    }

    /**
     * Process templated JSON to create final mDoc structure
     */
    public static Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            // Extract basic fields
            if (templateNode.has("docType")) {
                finalMDoc.put("docType", templateNode.get("docType").asText());
            }
            if (templateNode.has("holderId")) {
                finalMDoc.put("holderId", templateNode.get("holderId").asText());
            }

            if (templateNode.has("validityInfo")) {
                JsonNode validityInfo = templateNode.get("validityInfo");
                Map<String, Object> validity = objectMapper.convertValue(validityInfo, Map.class);
                finalMDoc.put("validityInfo", validity);
            }

            if (templateParams.containsKey("_issuer")) {
                finalMDoc.put("issuer", templateParams.get("_issuer"));
            }

            // Process namespaces
            Map<String, Object> nameSpaces = new HashMap<>();

            if (templateNode.has("nameSpaces")) {
                JsonNode nameSpacesNode = templateNode.get("nameSpaces");
                nameSpacesNode.fieldNames().forEachRemaining(namespaceName -> {
                    try {
                        JsonNode namespaceItems = nameSpacesNode.get(namespaceName);
                        List<Map<String, Object>> processedItems = processNamespaceItems(namespaceItems, templateParams);
                        nameSpaces.put(namespaceName, processedItems);
                    } catch (Exception e) {
                        log.error("Error processing namespace {}: {}", namespaceName, e.getMessage());
                    }
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
    public static List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems, Map<String, Object> templateParams) {
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

        // add missing fields from templateParams
        processedItems = addMissingFields(processedItems, templateParams);

        return processedItems;
    }

    /**
     * Add missing fields from templateParams that are not present in the template
     */
    public static List<Map<String, Object>> addMissingFields(List<Map<String, Object>> existingItems, Map<String, Object> templateParams) {
        Set<String> forbiddenIdentifiers = Set.of("templateName", "issuer", "issuerURI");

        for (Map.Entry<String, Object> param : templateParams.entrySet()) {
            Set<Integer> digestIDs = existingItems.stream()
                    .map(item -> (Integer) item.get("digestID"))
                    .collect(Collectors.toSet());
            Set<String> existingIdentifiers = existingItems.stream()
                    .map(item -> (String) item.get("elementIdentifier"))
                    .collect(Collectors.toSet());
            String identifier = param.getKey();

            // Skip if field already exists in template or not present in templateParams
            if (existingIdentifiers.contains(identifier) || identifier.startsWith("_") || forbiddenIdentifiers.contains(identifier)) {
                continue;
            }

            Object value = templateParams.get(identifier);
            if (value != null) {
                Map<String, Object> newItem = new HashMap<>();
                newItem.put("digestID", calculateMex(digestIDs));
                newItem.put("elementIdentifier", identifier);
                newItem.put("elementValue", value);
                existingItems.add(newItem);
            }
        }

        return existingItems;
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

                // Convert byte array to hex string
                String randomHex = bytesToHex(randomSalt);

                // Clone element with random salt as hex string
                Map<String, Object> saltedElement = new HashMap<>(element);
                saltedElement.put("random", randomSalt);

                saltedElements.add(saltedElement);
            }

            saltedNamespaces.put(namespaceName, saltedElements);
        }

        return saltedNamespaces;
    }

    // Helper method to convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }

    /**
     * Calculates SHA-256 digests for salted elements
     */
    public static Map<String, Object> calculateDigests(
            Map<String, Object> saltedNamespaces,
            Map<String, Map<Integer, byte[]>> namespaceDigests) throws Exception {

        Map<String, Object> processedNamespaces = new HashMap<>();

        for (Map.Entry<String, Object> namespaceEntry : saltedNamespaces.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            List<Map<String, Object>> elements = (List<Map<String, Object>>) namespaceEntry.getValue();

            List<byte[]> processedElements = new ArrayList<>();
            Map<Integer, byte[]> digestMap = new HashMap<>();

            for (Map<String, Object> element : elements) {
                // Encode to CBOR for digest calculation
                byte[] cborElement = MDocUtils.encodeToCBOR(element);

                // Calculate SHA-256 digest
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] elementDigest = digest.digest(cborElement);

                // Store digest by digestID
                Integer digestID = (Integer) element.get("digestID");
                digestMap.put(digestID, elementDigest);

                processedElements.add(cborElement);
            }

            processedNamespaces.put(namespaceName, processedElements);
            namespaceDigests.put(namespaceName, digestMap);
        }

        return processedNamespaces;
    }

    /**
     * Encodes an object to CBOR bytes
     */
//    public static byte[] encodeToCBOR(Object obj) throws Exception {
//        try {
//            Object preprocessedData = preprocessForCBOR(obj);
//            return cborMapper.writeValueAsBytes(preprocessedData);
//        } catch (Exception e) {
//            log.error("Error encoding to CBOR: {}", e.getMessage(), e);
//            throw new Exception("CBOR encoding failed: " + e.getMessage(), e);
//        }
//    }
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

        if (obj instanceof String) {
            String str = (String) obj;

            // Check if it's a date string and should be encoded with CBOR tag 1004
            if (isDateOnlyString(str)) {
                return createCBORTaggedDate(str);
            }

            // Check if it's a hex string that should be byte array
            if (str.matches("^[0-9a-fA-F]+$") && str.length() % 2 == 0 && str.length() > 10) {
                return hexStringToByteArray(str);
            }

            return str;
        }

        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            Map<String, Object> processedMap = new HashMap<>();

            for (Map.Entry<String, Object> entry : map.entrySet()) {
                processedMap.put(entry.getKey(), preprocessForCBOR(entry.getValue()));
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

        if (obj instanceof byte[]) {
            return obj; // Already byte array
        }

        return obj; // Numbers, booleans, etc.
    }


    // Add this helper method
    private static DataItem convertToDataItem(Object obj) {
        if (obj == null) {
            return SimpleValue.NULL;
        }
        if (obj instanceof String) {
            return new UnicodeString((String) obj);
        }
        if (obj instanceof Integer) {
            return new UnsignedInteger((Integer) obj);
        }
        if (obj instanceof Long) {
            return new UnsignedInteger((Long) obj);
        }
        if (obj instanceof Boolean) {
            return (Boolean) obj ? SimpleValue.TRUE : SimpleValue.FALSE;
        }
        if (obj instanceof byte[]) {
            return new ByteString((byte[]) obj);
        }
        if (obj instanceof java.util.Map) {
            co.nstant.in.cbor.model.Map map = new co.nstant.in.cbor.model.Map();
            for (Object entry : ((java.util.Map<?, ?>) obj).entrySet()) {
                java.util.Map.Entry<?, ?> mapEntry = (java.util.Map.Entry<?, ?>) entry;
                map.put(convertToDataItem(mapEntry.getKey()), convertToDataItem(mapEntry.getValue()));
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
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                    + Character.digit(hexStr.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Creates the Mobile Security Object (MSO) structure
     */
    public static Map<String, Object> createMobileSecurityObject(
            Map<String, Object> mDocJson,
            Map<String, Map<Integer, byte[]>> namespaceDigests,
            String appID, String refID) throws Exception {

        Map<String, Object> mso = new HashMap<>();
        mso.put("version", "1.0");
        mso.put("digestAlgorithm", "SHA-256");

        // Create valueDigests structure
        Map<String, Object> valueDigests = new HashMap<>();
        for (Map.Entry<String, Map<Integer, byte[]>> namespaceEntry : namespaceDigests.entrySet()) {
            String namespaceName = namespaceEntry.getKey();
            Map<Integer, byte[]> digests = namespaceEntry.getValue();

            Map<Integer, byte[]> digestBytes = new HashMap<>();
            for (Map.Entry<Integer, byte[]> digestEntry : digests.entrySet()) {
                digestBytes.put(digestEntry.getKey(), digestEntry.getValue());
            }
            valueDigests.put(namespaceName, digestBytes);
        }
        mso.put("valueDigests", valueDigests);

        // Add document metadata
        mso.put("docType", mDocJson.get("docType"));

        // Create validity info with current timestamp
        Map<String, Object> validityInfo = new HashMap<>();
        String currentTime = ZonedDateTime.now(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));

        if (mDocJson.containsKey("validityInfo")) {
            Map<String, Object> originalValidity = (Map<String, Object>) mDocJson.get("validityInfo");
            validityInfo.put("validFrom", originalValidity.get("validFrom"));
            validityInfo.put("validUntil", originalValidity.get("validUntil"));
        }
        mso.put("validityInfo", validityInfo);

        // Add device key info (placeholder - should be from wallet's PoP)
        Map<String, Object> deviceKeyInfo = createDeviceKeyInfo(mDocJson.get("holderId"));
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
        Map<String, Object> deviceKey = mapper.readValue(decodedJson, Map.class);

        Map<String, Object> deviceKeyInfo = new HashMap<>();
        deviceKeyInfo.put("deviceKey", deviceKey);

        return deviceKeyInfo;
    }

    /**
     * Signs the MSO using COSE_Sign1 structure
     */
//    public static byte[] signMSOWithCOSE(Map<String, Object> mso, String appID, String refID,
//                                   String signAlgorithm, DIDDocumentUtil didDocumentUtil, SignatureServicev2 signatureService) throws Exception {
//        try {
//            log.info("Starting COSE signing for MSO with algorithm: {}", signAlgorithm);
//
//            // Step 1: Encode MSO payload to CBOR
//            byte[] msoPayload = encodeToCBOR(mso);
//            log.debug("MSO payload encoded to CBOR, size: {} bytes", msoPayload.length);
//
//            // Step 2: Get certificate chain from KeyManager
//            CertificateResponseDTO certificateResponse = didDocumentUtil.getCertificateDataResponseDto(appID, refID);
//            String certificateData = certificateResponse.getCertificateData();
//
//            // Parse certificate chain - assuming PEM format
//            List<byte[]> certificateChain = parseCertificateChain(certificateData);
//
//            // Step 3: Create COSE_Sign1 protected header
//            Map<String, Object> protectedHeader = new HashMap<>();
//            protectedHeader.put(1, getCoseAlgorithmId(signAlgorithm)); // alg parameter
//
//            // Step 4: Create unprotected header with certificate chain
//            Map<String, Object> unprotectedHeader = new HashMap<>();
//            unprotectedHeader.put(33, certificateChain); // x5c parameter (certificate chain)
//
//            // Step 5: Encode protected header to CBOR
//            byte[] protectedHeaderCbor = encodeToCBOR(protectedHeader);
//
//            // Step 6: Create Sig_structure for signing according to RFC 8152
//            // Sig_structure = [
//            //   context,           // "Signature1" for COSE_Sign1
//            //   protected,         // encoded protected header
//            //   external_aad,      // empty for detached signature
//            //   payload           // MSO payload
//            // ]
//            List<Object> sigStructure = Arrays.asList(
//                    "Signature1",           // context
//                    protectedHeaderCbor,    // protected header (encoded)
//                    new byte[0],           // external_aad (empty)
//                    msoPayload             // payload
//            );
//
//            byte[] toBeSigned = encodeToCBOR(sigStructure);
//            log.debug("Sig_structure created, size: {} bytes", toBeSigned.length);
//
//            // Step 7: Sign the Sig_structure using KeyManager
//            String signatureResponse = signatureService.sign(appID, refID, toBeSigned, signAlgorithm);
//            byte[] signature = Base64.getDecoder().decode(signatureResponse);
//            log.debug("Signature generated, size: {} bytes", signature.length);
//
//            // Step 8: Create final COSE_Sign1 structure
//            // COSE_Sign1 = [
//            //   protected,      // encoded protected header
//            //   unprotected,    // unprotected header map
//            //   payload,        // null for detached signature
//            //   signature       // signature bytes
//            // ]
//            List<Object> coseSign1 = Arrays.asList(
//                    protectedHeaderCbor,    // protected header (encoded)
//                    unprotectedHeader,      // unprotected header (map)
//                    null,                   // payload (null for detached signature)
//                    signature               // signature
//            );
//
//            // Step 9: Encode COSE_Sign1 to CBOR and wrap with Tag 18
//            byte[] coseSign1Cbor = encodeToCBOR(coseSign1);
//            byte[] taggedCoseSign1 = wrapWithCBORTag18(coseSign1Cbor);
//
//            log.info("COSE signing completed successfully, final size: {} bytes", taggedCoseSign1.length);
//            return taggedCoseSign1;

//        } catch (Exception e) {
//            log.error("Error during COSE signing: {}", e.getMessage(), e);
//            throw new Exception("COSE signing failed: " + e.getMessage(), e);
//        }
//    }

    private static List<byte[]> parseCertificateChain(String certificateData) throws Exception {
        List<byte[]> certificateChain = new ArrayList<>();

        try {
            // Remove PEM headers/footers and decode base64
            String cleanCert = certificateData
                    .replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");

            byte[] certBytes = Base64.getDecoder().decode(cleanCert);
            certificateChain.add(certBytes);

            log.debug("Parsed certificate chain with {} certificates", certificateChain.size());
            return certificateChain;

        } catch (Exception e) {
            log.error("Error parsing certificate chain: {}", e.getMessage(), e);
            throw new Exception("Failed to parse certificate chain: " + e.getMessage(), e);
        }
    }



    public static byte[] wrapWithCBORTag24(Map<String, Object> element) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);

            DataItem elementDataItem = convertToDataItem(element);
            elementDataItem.setTag(24);  // Tag the actual structure
            encoder.encode(elementDataItem);

            return baos.toByteArray();
        } catch (CborException e) {
            throw new IOException("Failed to wrap with CBOR tag 24", e);
        }
    }

    public static byte[] wrapWithCBORTag18(byte[] cborData) throws IOException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CborEncoder encoder = new CborEncoder(baos);

            ByteString byteString = new ByteString(cborData);
            byteString.setTag(18);
            encoder.encode(byteString);

            return baos.toByteArray();
        } catch (CborException e) {
            throw new IOException("Failed to wrap with CBOR tag 18", e);
        }
    }


    /**
     * Creates the final IssuerSigned structure
     */
    public static Map<String, Object> createIssuerSignedStructure(
            Map<String, Object> processedNamespaces,
            byte[] signedMSO) {

        Map<String, Object> issuerSigned = new HashMap<>();
        issuerSigned.put("nameSpaces", processedNamespaces);
        issuerSigned.put("issuerAuth", signedMSO);

        return issuerSigned;
    }

}
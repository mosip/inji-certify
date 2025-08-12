/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Utility class for mDoc (Mobile Document) specific operations.
 * Provides helper methods for mDoc structure creation and manipulation.
 */
@Slf4j
public class MDocUtils {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Process templated JSON to create final mDoc structure
     */
    public static Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams) {
        try {
            JsonNode templateNode = objectMapper.readTree(templatedJSON);
            Map<String, Object> finalMDoc = new HashMap<>();

            // Extract basic fields
            extractBasicFields(templateNode, finalMDoc, templateParams);

            // Process namespaces
            Map<String, Object> nameSpaces = processNamespaces(templateNode, templateParams);
            finalMDoc.put("nameSpaces", nameSpaces);

            return finalMDoc;

        } catch (Exception e) {
            log.error("Error processing templated JSON: {}", e.getMessage(), e);
            return new HashMap<>();
        }
    }

    /**
     * Extract basic fields from template node
     */
    private static void extractBasicFields(JsonNode templateNode, Map<String, Object> finalMDoc, Map<String, Object> templateParams) {
        if (templateNode.has("docType")) {
            finalMDoc.put("docType", templateNode.get("docType").asText());
        }

        if (templateNode.has("validityInfo")) {
            JsonNode validityInfo = templateNode.get("validityInfo");
            Map<String, Object> validity = objectMapper.convertValue(validityInfo, Map.class);
            finalMDoc.put("validityInfo", validity);
        }

        if (templateParams.containsKey("_issuer")) {
            finalMDoc.put("issuer", templateParams.get("_issuer"));
        }
    }

    /**
     * Process namespaces from template node
     */
    private static Map<String, Object> processNamespaces(JsonNode templateNode, Map<String, Object> templateParams) {
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

        return nameSpaces;
    }

    /**
     * Process items within a namespace
     */
    private static List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems, Map<String, Object> templateParams) {
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

        // Now add missing fields from templateParams
        processedItems = addMissingFields(processedItems, templateParams);

        return processedItems;
    }

    /**
     * Add missing fields from templateParams that are not present in the template
     */
    private static List<Map<String, Object>> addMissingFields(List<Map<String, Object>> existingItems, Map<String, Object> templateParams) {
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
     * Convert JsonNode to appropriate Java object
     */
    private static Object convertJsonNode(JsonNode node) {
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

//    private static final DateTimeFormatter ISO_DATETIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");
//
//    /**
//     * Create an IssuerSignedItem for mDoc credential
//     *
//     * @param digestId The digest ID for the item
//     * @param elementIdentifier The element identifier
//     * @param elementValue The element value
//     * @return IssuerSignedItem instance
//     * @throws CertifyException if creation fails
//     */
//    public static IssuerSignedItem createIssuerSignedItem(int digestId, String elementIdentifier, Object elementValue) throws CertifyException {
//        try {
//            byte[] salt = DigestUtils.generateSalt();
//            IssuerSignedItem item = new IssuerSignedItem(digestId, elementIdentifier, elementValue);
//            item.setRandom(salt);
//            return item;
//        } catch (Exception e) {
//            log.error("Failed to create IssuerSignedItem for element {}: {}", elementIdentifier, e.getMessage());
//            throw new CertifyException("Failed to create IssuerSignedItem: " + e.getMessage());
//        }
//    }
//
//    /**
//     * Calculate digest for an IssuerSignedItem
//     *
//     * @param item The IssuerSignedItem
//     * @return SHA-256 digest bytes
//     * @throws CertifyException if digest calculation fails
//     */
//    public static byte[] calculateItemDigest(IssuerSignedItem item) throws CertifyException {
//        try {
//
//            Map<String, Object> cborMap = Map.of(
//                    "digestId", item.getDigestID(),
//                    "salt", item.getRandom(),
//                    "elementIdentifier", item.getElementIdentifier(),
//                    "elementValue", item.getElementValue()
//            );
//            byte[] cborBytes = CBORUtils.encodeMap(cborMap);
//            return DigestUtils.calculateSHA256(cborBytes);
//        } catch (Exception e) {
//            log.error("Failed to calculate digest for item {}: {}", item.getElementIdentifier(), e.getMessage());
//            throw new CertifyException("Failed to calculate item digest: " + e.getMessage());
//        }
//    }
//
//    /**
//     * Create digest mapping for Mobile Security Object (MSO)
//     *
//     * @param nameSpace The namespace for the items
//     * @param items List of IssuerSignedItem objects
//     * @return Map of digestId to digest bytes
//     * @throws CertifyException if digest calculation fails
//     */
//    public static Map<Integer, byte[]> createDigestMapping(String nameSpace, List<IssuerSignedItem> items) throws CertifyException {
//        Map<Integer, byte[]> digestMapping = new HashMap<>();
//
//        for (IssuerSignedItem item : items) {
//            byte[] digest = calculateItemDigest(item);
//            digestMapping.put(item.getDigestID(), digest);
//        }
//
//        log.debug("Created digest mapping for namespace {} with {} items", nameSpace, items.size());
//        return digestMapping;
//    }
//
//    /**
//     * Create validity info for mDoc
//     *
//     * @param validFrom Valid from date
//     * @param validUntil Valid until date
//     * @return Validity info map
//     */
//    public static Map<String, Object> createValidityInfo(LocalDateTime validFrom, LocalDateTime validUntil) {
//        Map<String, Object> validityInfo = new HashMap<>();
//
//        if (validFrom != null) {
//            validityInfo.put(MDocConstants.VALID_FROM, formatDateTime(validFrom));
//        }
//
//        if (validUntil != null) {
//            validityInfo.put(MDocConstants.VALID_UNTIL, formatDateTime(validUntil));
//        }
//
//        return validityInfo;
//    }
//
//    /**
//     * Create default validity info (valid from now, valid for 1 year)
//     *
//     * @return Default validity info map
//     */
//    public static Map<String, Object> createDefaultValidityInfo() {
//        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);
//        LocalDateTime validUntil = now.plusYears(1);
//        return createValidityInfo(now, validUntil);
//    }
//
//    /**
//     * Format LocalDateTime to ISO string format for mDoc
//     *
//     * @param dateTime The datetime to format
//     * @return ISO formatted datetime string
//     */
//    public static String formatDateTime(LocalDateTime dateTime) {
//        return dateTime.atOffset(ZoneOffset.UTC).format(ISO_DATETIME_FORMATTER);
//    }
//
//    /**
//     * Generate unique digest IDs for a list of element identifiers
//     *
//     * @param elementIdentifiers List of element identifiers
//     * @return Map of element identifier to digest ID
//     */
//    public static Map<String, Integer> generateDigestIds(List<String> elementIdentifiers) {
//        Map<String, Integer> digestIds = new HashMap<>();
//
//        for (int i = 0; i < elementIdentifiers.size(); i++) {
//            digestIds.put(elementIdentifiers.get(i), i);
//        }
//
//        return digestIds;
//    }
//
//    /**
//     * Create device key info for mDoc (placeholder for future implementation)
//     *
//     * @param deviceKey The device public key
//     * @return Device key info map
//     */
//    public static Map<String, Object> createDeviceKeyInfo(String deviceKey) {
//        Map<String, Object> deviceKeyInfo = new HashMap<>();
//
//        if (deviceKey != null && !deviceKey.isEmpty()) {
//            deviceKeyInfo.put(MDocConstants.DEVICE_KEY_INFO, deviceKey);
//        }
//
//        return deviceKeyInfo;
//    }
//
//    /**
//     * Validate mDoc namespace format
//     *
//     * @param namespace The namespace to validate
//     * @return true if valid, false otherwise
//     */
//    public static boolean isValidNamespace(String namespace) {
//        return namespace != null && !namespace.trim().isEmpty() &&
//                namespace.matches("^[a-zA-Z0-9._-]+$");
//    }
//
//    /**
//     * Validate element identifier format
//     *
//     * @param elementIdentifier The element identifier to validate
//     * @return true if valid, false otherwise
//     */
//    public static boolean isValidElementIdentifier(String elementIdentifier) {
//        return elementIdentifier != null && !elementIdentifier.trim().isEmpty() &&
//                elementIdentifier.matches("^[a-zA-Z0-9._-]+$");
//    }
//
//    /**
//     * Create mDoc version info
//     *
//     * @return Version info string
//     */
//    public static String createVersionInfo() {
//        return MDocConstants.MDOC_VERSION;
//    }
//
//    /**
//     * Convert byte array to Base64 string for transport
//     *
//     * @param bytes The bytes to encode
//     * @return Base64 encoded string
//     */
//    public static String encodeBase64(byte[] bytes) {
//        return Base64.getEncoder().encodeToString(bytes);
//    }
//
//    /**
//     * Decode Base64 string to byte array
//     *
//     * @param base64String The Base64 string to decode
//     * @return Decoded bytes
//     * @throws CertifyException if decoding fails
//     */
//    public static byte[] decodeBase64(String base64String) throws CertifyException {
//        try {
//            return Base64.getDecoder().decode(base64String);
//        } catch (IllegalArgumentException e) {
//            log.error("Failed to decode Base64 string: {}", e.getMessage());
//            throw new CertifyException("Base64 decoding failed: " + e.getMessage());
//        }
//    }
//
//    /**
//     * Create a structured mDoc response with proper formatting
//     *
//     * @param docType The document type
//     * @param issuerSignedItems Map of namespace to items
//     * @param issuerAuth The issuer authentication data
//     * @return Structured mDoc response
//     */
//    public static Map<String, Object> createMDocResponse(String docType,
//                                                         Map<String, List<IssuerSignedItem>> issuerSignedItems,
//                                                         byte[] issuerAuth) {
//        Map<String, Object> mDocResponse = new HashMap<>();
//
//        mDocResponse.put(MDocConstants.DOC_TYPE, docType);
//        mDocResponse.put(MDocConstants.ISSUER_SIGNED, createIssuerSignedStructure(issuerSignedItems, issuerAuth));
//
//        return mDocResponse;
//    }
//
//    /**
//     * Create issuer signed structure for mDoc
//     *
//     * @param issuerSignedItems Map of namespace to items
//     * @param issuerAuth The issuer authentication data
//     * @return Issuer signed structure
//     */
//    private static Map<String, Object> createIssuerSignedStructure(Map<String, List<IssuerSignedItem>> issuerSignedItems,
//                                                                   byte[] issuerAuth) {
//        Map<String, Object> issuerSigned = new HashMap<>();
//
//        // Convert IssuerSignedItems to proper structure
//        Map<String, Object> namespaces = new HashMap<>();
//        for (Map.Entry<String, List<IssuerSignedItem>> entry : issuerSignedItems.entrySet()) {
//            List<List<Object>> itemsArray = new ArrayList<>();
//            for (IssuerSignedItem item : entry.getValue()) {
//                itemsArray.add(Arrays.asList(
//                        item.getDigestID(),
//                        item.getRandom(),
//                        item.getElementIdentifier(),
//                        item.getElementValue()
//                ));
//            }
//            namespaces.put(entry.getKey(), itemsArray);
//        }
//
//        issuerSigned.put(MDocConstants.NAMESPACES, namespaces);
//        issuerSigned.put(MDocConstants.ISSUER_AUTH, issuerAuth);
//
//        return issuerSigned;
//    }
}
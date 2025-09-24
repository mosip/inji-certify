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

    /**
     * Process templated JSON to create final mDoc structure
     */
    public Map<String, Object> processTemplatedJson(String templatedJSON, Map<String, Object> templateParams) {
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
    private void extractBasicFields(JsonNode templateNode, Map<String, Object> finalMDoc, Map<String, Object> templateParams) {
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
    private Map<String, Object> processNamespaces(JsonNode templateNode, Map<String, Object> templateParams) {
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
    private List<Map<String, Object>> processNamespaceItems(JsonNode namespaceItems, Map<String, Object> templateParams) {
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
    private List<Map<String, Object>> addMissingFields(List<Map<String, Object>> existingItems, Map<String, Object> templateParams) {
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
    public int calculateMex(Set<Integer> numbers) {
        int mex = 0;
        while (numbers.contains(mex)) {
            mex++;
        }
        return mex;
    }
}
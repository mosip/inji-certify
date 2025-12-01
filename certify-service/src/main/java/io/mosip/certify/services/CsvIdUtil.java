/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility service to load and manage CSV user IDs
 * Reads IDs from the same CSV file used by MockCSVDataProviderPlugin
 * for use as transaction IDs in OAuth 2.0 flow
 */
@Slf4j
@Service
public class CsvIdUtil {

    @Value("${mosip.certify.mock.data-provider.csv-registry-uri:}")
    private String csvRegistryUri;

    @Value("${mosip.certify.mock.data-provider.csv.identifier-column:id}")
    private String identifierColumn;

    private List<String> csvIds = new ArrayList<>();

    /**
     * Load CSV IDs at startup
     */
    @PostConstruct
    public void loadCsvIds() {
        if (!StringUtils.hasText(csvRegistryUri)) {
            log.warn("CSV registry URI not configured. CSV ID lookup will not be available.");
            return;
        }

        try {
            log.info("Loading CSV IDs from: {}, identifier column: {}", csvRegistryUri, identifierColumn);
            
            List<String> lines = readCsvFile();
            if (lines.isEmpty()) {
                log.error("CSV file is empty or contains no data rows");
                throw new IllegalStateException("CSV file must contain at least one data row");
            }

            // First line is header - extract column index
            String headerLine = lines.get(0);
            String[] headers = parseCsvLine(headerLine);
            int identifierColumnIndex = findColumnIndex(headers, identifierColumn);
            
            if (identifierColumnIndex < 0) {
                log.error("Identifier column '{}' not found in CSV headers: {}", identifierColumn, headerLine);
                throw new IllegalStateException("Identifier column '" + identifierColumn + "' not found in CSV");
            }

            // Extract IDs from remaining lines
            for (int i = 1; i < lines.size(); i++) {
                String[] values = parseCsvLine(lines.get(i));
                if (values.length > identifierColumnIndex) {
                    String id = values[identifierColumnIndex].trim();
                    if (StringUtils.hasText(id)) {
                        csvIds.add(id);
                    }
                }
            }

            if (csvIds.isEmpty()) {
                log.error("No valid IDs extracted from CSV file");
                throw new IllegalStateException("CSV file must contain at least one valid ID in column '" + identifierColumn + "'");
            }

            log.info("Successfully loaded {} IDs from CSV file using identifier column '{}'", 
                    csvIds.size(), identifierColumn);

        } catch (Exception e) {
            log.error("Failed to load CSV IDs from: {}", csvRegistryUri, e);
            throw new IllegalStateException("Cannot start service - failed to load CSV IDs: " + e.getMessage(), e);
        }
    }

    /**
     * Read CSV file from classpath or file system
     */
    private List<String> readCsvFile() throws Exception {
        List<String> lines = new ArrayList<>();

        if (csvRegistryUri.startsWith("classpath:")) {
            // Read from classpath
            String resourcePath = csvRegistryUri.substring("classpath:".length());
            Resource resource = new ClassPathResource(resourcePath);
            
            if (!resource.exists()) {
                throw new IllegalStateException("CSV file not found in classpath: " + resourcePath);
            }

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(resource.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }
            log.debug("Read {} lines from classpath resource: {}", lines.size(), resourcePath);
        } else {
            // Read from file system
            File csvFile = new File(csvRegistryUri);
            if (!csvFile.exists() || !csvFile.isFile()) {
                throw new IllegalStateException("CSV file not found at path: " + csvRegistryUri);
            }

            lines = Files.readAllLines(Paths.get(csvRegistryUri));
            log.debug("Read {} lines from file system: {}", lines.size(), csvRegistryUri);
        }

        return lines;
    }

    /**
     * Parse CSV line handling quoted values
     */
    private String[] parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                values.add(current.toString());
                current = new StringBuilder();
            } else {
                current.append(c);
            }
        }
        values.add(current.toString());
        
        return values.toArray(new String[0]);
    }

    /**
     * Find column index by name (case-insensitive)
     */
    private int findColumnIndex(String[] headers, String columnName) {
        for (int i = 0; i < headers.length; i++) {
            if (headers[i].trim().equalsIgnoreCase(columnName)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Get a CSV ID to use as transaction ID
     * For testing: Returns first available ID
     * 
     * @return CSV user ID
     * @throws CertifyException if no IDs are available
     */
    public String getCsvId() throws CertifyException {
        if (csvIds.isEmpty()) {
            throw new CertifyException("no_csv_ids", 
                "No CSV IDs available. CSV file may not be loaded or is empty.");
        }

        String selectedId = csvIds.get(0);
        log.debug("Selected CSV ID for transaction: {}", selectedId);
        return selectedId;
    }

    /**
     * Get number of available CSV IDs
     */
    public int getAvailableIdCount() {
        return csvIds.size();
    }
}


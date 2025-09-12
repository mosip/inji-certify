/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Service for loading and managing presentation definition configurations
 * Loads configuration from JSON file similar to inji-verify implementation
 */
@Slf4j
@Service
public class PresentationDefinitionConfigService {

    private final ResourceLoader resourceLoader;
    private final ObjectMapper objectMapper;

    @Value("${mosip.certify.presentation-definition.config-file:classpath:certify-config.json}")
    private String configFilePath;


    @Value("${mosip.certify.presentation-definition.default-id:default-presentation}")
    private String defaultPresentationId;

    private VerifiableClaimsConfig verifiableClaimsConfig;

    public PresentationDefinitionConfigService(ResourceLoader resourceLoader, ObjectMapper objectMapper) {
        this.resourceLoader = resourceLoader;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        loadConfiguration();
    }

    /**
     * Load verifiable claims configuration from JSON file
     */
    private void loadConfiguration() {
        try {
            log.info("Loading presentation definition configuration from: {}", configFilePath);
            
            Resource resource = resourceLoader.getResource(configFilePath);
            if (!resource.exists()) {
                log.error("PRODUCTION ERROR: Configuration file not found at: {}. This is REQUIRED for production!", configFilePath);
                throw new RuntimeException("Presentation definition configuration file is required: " + configFilePath);
            }

            try (InputStream inputStream = resource.getInputStream()) {
                verifiableClaimsConfig = objectMapper.readValue(inputStream, VerifiableClaimsConfig.class);
                log.info("Successfully loaded {} verifiable claims from configuration", 
                        verifiableClaimsConfig.getVerifiableClaims().size());
                
                // Log loaded credential types for debugging
                verifiableClaimsConfig.getVerifiableClaims().forEach(claim -> 
                    log.debug("Loaded credential type: {} - {}", claim.getType(), claim.getName()));
                
            }
        } catch (IOException e) {
            log.error("PRODUCTION ERROR: Failed to load presentation definition configuration", e);
            throw new RuntimeException("Cannot load presentation definition configuration: " + e.getMessage(), e);
        }
    }


    /**
     * Get presentation definition for a specific credential type
     * 
     * @param credentialType The credential type to get definition for
     * @return PresentationDefinition for the credential type
     */
    public PresentationDefinition getPresentationDefinition(String credentialType) {
        log.debug("Getting presentation definition for credential type: {}", credentialType);
        
        if (verifiableClaimsConfig == null || verifiableClaimsConfig.getVerifiableClaims() == null) {
            log.error("No presentation definition configuration loaded - this is required for production");
            throw new RuntimeException("Presentation definition configuration not loaded - check application configuration");
        }

        // Find matching credential type
        Optional<VerifiableClaimsConfig.VerifiableClaim> matchingClaim = verifiableClaimsConfig
                .getVerifiableClaims()
                .stream()
                .filter(claim -> credentialType.equals(claim.getType()))
                .findFirst();

        if (matchingClaim.isPresent()) {
            log.debug("Found matching configuration for credential type: {}", credentialType);
            return convertToPresentationDefinition(matchingClaim.get());
        }

        log.error("No presentation definition configured for credential type: {}", credentialType);
        throw new RuntimeException("No presentation definition configured for credential type: " + credentialType);
    }

    /**
     * Get all available credential types from configuration
     * 
     * @return List of available credential types
     */
    public List<String> getAvailableCredentialTypes() {
        if (verifiableClaimsConfig == null || verifiableClaimsConfig.getVerifiableClaims() == null) {
            throw new RuntimeException("No credential types available - configuration not loaded");
        }
        
        return verifiableClaimsConfig.getVerifiableClaims()
                .stream()
                .map(VerifiableClaimsConfig.VerifiableClaim::getType)
                .filter(StringUtils::hasText)
                .toList();
    }

    /**
     * Get default presentation definition (usually the essential one)
     * 
     * @return Default PresentationDefinition
     */
    public PresentationDefinition getDefaultPresentationDefinition() {
        log.debug("Getting default presentation definition");
        
        if (verifiableClaimsConfig == null || verifiableClaimsConfig.getVerifiableClaims() == null || 
            verifiableClaimsConfig.getVerifiableClaims().isEmpty()) {
            throw new RuntimeException("No default presentation definition available - configuration not loaded");
        }
        
        // Use the first essential claim as default, or first claim if no essential ones
        Optional<VerifiableClaimsConfig.VerifiableClaim> defaultClaim = verifiableClaimsConfig
                .getVerifiableClaims()
                .stream()
                .filter(claim -> Boolean.TRUE.equals(claim.getEssential()))
                .findFirst();
                
        if (defaultClaim.isEmpty()) {
            // No essential claims, use first available
            defaultClaim = verifiableClaimsConfig.getVerifiableClaims().stream().findFirst();
        }
        
        if (defaultClaim.isEmpty()) {
            throw new RuntimeException("No presentation definition available in configuration");
        }
        
        return getPresentationDefinition(defaultClaim.get().getType());
    }

    /**
     * Convert VerifiableClaim configuration to PresentationDefinition
     */
    private PresentationDefinition convertToPresentationDefinition(VerifiableClaimsConfig.VerifiableClaim claim) {
        PresentationDefinition presentationDefinition = new PresentationDefinition();
        presentationDefinition.setId(defaultPresentationId);

        if (claim.getDefinition() != null && claim.getDefinition().getInputDescriptors() != null) {
            List<InputDescriptor> inputDescriptors = claim.getDefinition().getInputDescriptors()
                    .stream()
                    .map(this::convertInputDescriptor)
                    .toList();
            presentationDefinition.setInputDescriptors(inputDescriptors);
        }

        log.debug("Converted credential type '{}' to presentation definition with {} input descriptors", 
                 claim.getType(), presentationDefinition.getInputDescriptors().size());
        
        return presentationDefinition;
    }

    /**
     * Convert configuration InputDescriptor to DTO InputDescriptor
     */
    private InputDescriptor convertInputDescriptor(VerifiableClaimsConfig.InputDescriptor configDescriptor) {
        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId(configDescriptor.getId());

        if (configDescriptor.getConstraints() != null && configDescriptor.getConstraints().getFields() != null) {
            InputConstraints constraints = new InputConstraints();
            List<io.mosip.certify.core.dto.FieldConstraint> fields = configDescriptor.getConstraints().getFields()
                    .stream()
                    .map(this::convertFieldConstraint)
                    .toList();
            constraints.setFields(fields);
            inputDescriptor.setConstraints(constraints);
        }

        return inputDescriptor;
    }

    /**
     * Convert configuration FieldConstraint to DTO FieldConstraint
     */
    private io.mosip.certify.core.dto.FieldConstraint convertFieldConstraint(VerifiableClaimsConfig.FieldConstraint configField) {
        io.mosip.certify.core.dto.FieldConstraint fieldConstraint = new io.mosip.certify.core.dto.FieldConstraint();
        fieldConstraint.setPath(configField.getPath());
        return fieldConstraint;
    }


    /**
     * Reload configuration from file (useful for runtime updates)
     */
    public void reloadConfiguration() {
        log.info("Reloading presentation definition configuration");
        loadConfiguration();
    }
}

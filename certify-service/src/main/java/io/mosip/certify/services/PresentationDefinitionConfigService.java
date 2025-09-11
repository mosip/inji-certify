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
import org.springframework.cache.annotation.Cacheable;
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

    @Value("${mosip.certify.presentation-definition.default-credential-type:MOSIPVerifiableCredential}")
    private String defaultCredentialType;

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
                log.warn("Configuration file not found at: {}, will use default configuration", configFilePath);
                createDefaultConfiguration();
                return;
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
            log.error("Failed to load presentation definition configuration", e);
            createDefaultConfiguration();
        }
    }

    /**
     * Create default configuration when config file is not available
     */
    private void createDefaultConfiguration() {
        log.info("Creating default presentation definition configuration");
        
        VerifiableClaimsConfig defaultConfig = new VerifiableClaimsConfig();
        VerifiableClaimsConfig.VerifiableClaim defaultClaim = new VerifiableClaimsConfig.VerifiableClaim();
        
        defaultClaim.setName("Default Identity");
        defaultClaim.setType(defaultCredentialType);
        defaultClaim.setEssential(true);
        defaultClaim.setLogo("/assets/cert.png");
        
        // Create basic definition
        VerifiableClaimsConfig.ClaimDefinition definition = new VerifiableClaimsConfig.ClaimDefinition();
        definition.setPurpose("Relying party is requesting your digital ID for authentication");
        
        // Create format
        VerifiableClaimsConfig.Format format = new VerifiableClaimsConfig.Format();
        VerifiableClaimsConfig.LdpVc ldpVc = new VerifiableClaimsConfig.LdpVc();
        ldpVc.setProofType(Arrays.asList("RsaSignature2018"));
        format.setLdpVc(ldpVc);
        definition.setFormat(format);
        
        // Create input descriptor
        VerifiableClaimsConfig.InputDescriptor inputDescriptor = new VerifiableClaimsConfig.InputDescriptor();
        inputDescriptor.setId("default credential");
        inputDescriptor.setFormat(format);
        
        // Create constraints
        VerifiableClaimsConfig.Constraints constraints = new VerifiableClaimsConfig.Constraints();
        VerifiableClaimsConfig.FieldConstraint fieldConstraint = new VerifiableClaimsConfig.FieldConstraint();
        fieldConstraint.setPath(Arrays.asList("$.type"));
        
        VerifiableClaimsConfig.Filter filter = new VerifiableClaimsConfig.Filter();
        filter.setType("object");
        filter.setPattern(defaultCredentialType);
        fieldConstraint.setFilter(filter);
        
        constraints.setFields(Arrays.asList(fieldConstraint));
        inputDescriptor.setConstraints(constraints);
        definition.setInputDescriptors(Arrays.asList(inputDescriptor));
        
        defaultClaim.setDefinition(definition);
        defaultConfig.setVerifiableClaims(Arrays.asList(defaultClaim));
        
        this.verifiableClaimsConfig = defaultConfig;
        log.info("Default configuration created with credential type: {}", defaultCredentialType);
    }

    /**
     * Get presentation definition for a specific credential type
     * 
     * @param credentialType The credential type to get definition for
     * @return PresentationDefinition for the credential type
     */
    @Cacheable("presentationDefinitions")
    public PresentationDefinition getPresentationDefinition(String credentialType) {
        log.debug("Getting presentation definition for credential type: {}", credentialType);
        
        if (verifiableClaimsConfig == null || verifiableClaimsConfig.getVerifiableClaims() == null) {
            log.warn("No configuration loaded, creating fallback presentation definition");
            return createFallbackPresentationDefinition(credentialType);
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

        // Fallback to essential credential if specific type not found
        Optional<VerifiableClaimsConfig.VerifiableClaim> essentialClaim = verifiableClaimsConfig
                .getVerifiableClaims()
                .stream()
                .filter(claim -> Boolean.TRUE.equals(claim.getEssential()))
                .findFirst();

        if (essentialClaim.isPresent()) {
            log.debug("Using essential credential configuration as fallback for type: {}", credentialType);
            return convertToPresentationDefinition(essentialClaim.get());
        }

        // Final fallback
        log.warn("No matching or essential credential found, using fallback for type: {}", credentialType);
        return createFallbackPresentationDefinition(credentialType);
    }

    /**
     * Get all available credential types from configuration
     * 
     * @return List of available credential types
     */
    public List<String> getAvailableCredentialTypes() {
        if (verifiableClaimsConfig == null || verifiableClaimsConfig.getVerifiableClaims() == null) {
            return Arrays.asList(defaultCredentialType);
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
        return getPresentationDefinition(defaultCredentialType);
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
     * Create fallback presentation definition when configuration is not available
     */
    private PresentationDefinition createFallbackPresentationDefinition(String credentialType) {
        log.debug("Creating fallback presentation definition for credential type: {}", credentialType);
        
        PresentationDefinition presentationDefinition = new PresentationDefinition();
        presentationDefinition.setId(defaultPresentationId);

        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId("fallback-descriptor");

        InputConstraints constraints = new InputConstraints();
        io.mosip.certify.core.dto.FieldConstraint fieldConstraint = new io.mosip.certify.core.dto.FieldConstraint();
        fieldConstraint.setPath(Arrays.asList("$.type"));
        constraints.setFields(Arrays.asList(fieldConstraint));
        inputDescriptor.setConstraints(constraints);

        presentationDefinition.setInputDescriptors(Arrays.asList(inputDescriptor));

        log.debug("Created fallback presentation definition for credential type: {}", credentialType);
        return presentationDefinition;
    }

    /**
     * Reload configuration from file (useful for runtime updates)
     */
    public void reloadConfiguration() {
        log.info("Reloading presentation definition configuration");
        loadConfiguration();
    }
}

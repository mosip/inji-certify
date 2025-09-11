/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.PresentationDefinition;
import io.mosip.certify.services.PresentationDefinitionConfigService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Debug controller for testing presentation definition configuration
 * This controller provides endpoints to test the configuration service directly
 * without requiring the verify service integration
 */
@Slf4j
@RestController
@RequestMapping("/debug")
public class PresentationDefinitionDebugController {

    @Autowired
    private PresentationDefinitionConfigService presentationDefinitionConfigService;

    /**
     * Get presentation definition for a specific credential type
     * GET /debug/presentation-definition/{credentialType}
     */
    @GetMapping(value = "/presentation-definition/{credentialType}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getPresentationDefinition(@PathVariable String credentialType) {
        log.info("Debug request for presentation definition of credential type: {}", credentialType);
        
        try {
            PresentationDefinition definition = presentationDefinitionConfigService
                    .getPresentationDefinition(credentialType);
            
            Map<String, Object> response = new HashMap<>();
            response.put("credentialType", credentialType);
            response.put("presentationDefinition", definition);
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Successfully retrieved presentation definition for credential type: {}", credentialType);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to get presentation definition for credential type: {}", credentialType, e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get presentation definition");
            errorResponse.put("credentialType", credentialType);
            errorResponse.put("message", e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * Get default presentation definition
     * GET /debug/presentation-definition/default
     */
    @GetMapping(value = "/presentation-definition/default", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getDefaultPresentationDefinition() {
        log.info("Debug request for default presentation definition");
        
        try {
            PresentationDefinition definition = presentationDefinitionConfigService
                    .getDefaultPresentationDefinition();
            
            Map<String, Object> response = new HashMap<>();
            response.put("credentialType", "default");
            response.put("presentationDefinition", definition);
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Successfully retrieved default presentation definition");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to get default presentation definition", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get default presentation definition");
            errorResponse.put("message", e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * Get all available credential types
     * GET /debug/credential-types
     */
    @GetMapping(value = "/credential-types", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getAvailableCredentialTypes() {
        log.info("Debug request for available credential types");
        
        try {
            List<String> credentialTypes = presentationDefinitionConfigService
                    .getAvailableCredentialTypes();
            
            Map<String, Object> response = new HashMap<>();
            response.put("availableCredentialTypes", credentialTypes);
            response.put("count", credentialTypes.size());
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Successfully retrieved {} available credential types", credentialTypes.size());
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to get available credential types", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get available credential types");
            errorResponse.put("message", e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * Test credential type extraction logic
     * GET /debug/extract-credential-type?client_id=xxx
     */
    @GetMapping(value = "/extract-credential-type", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> extractCredentialType(@RequestParam String client_id) {
        log.info("Debug request to extract credential type for client_id: {}", client_id);
        
        try {
            // Simulate the same logic as in IarServiceImpl
            String credentialType = "MOSIPVerifiableCredential"; // default
            
            if (client_id != null) {
                if (client_id.contains("insurance")) {
                    credentialType = "InsuranceCredential";
                } else if (client_id.contains("mock")) {
                    credentialType = "MockVerifiableCredential";
                } else if (client_id.contains("land")) {
                    credentialType = "LandStatementCredential";
                }
            }
            
            // Get the presentation definition for this credential type
            PresentationDefinition definition = presentationDefinitionConfigService
                    .getPresentationDefinition(credentialType);
            
            Map<String, Object> response = new HashMap<>();
            response.put("clientId", client_id);
            response.put("extractedCredentialType", credentialType);
            response.put("presentationDefinition", definition);
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Successfully extracted credential type '{}' for client_id '{}'", credentialType, client_id);
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to extract credential type for client_id: {}", client_id, e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to extract credential type");
            errorResponse.put("clientId", client_id);
            errorResponse.put("message", e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    /**
     * Reload configuration from file
     * POST /debug/reload-configuration
     */
    @PostMapping(value = "/reload-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> reloadConfiguration() {
        log.info("Debug request to reload presentation definition configuration");
        
        try {
            presentationDefinitionConfigService.reloadConfiguration();
            
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Configuration reloaded successfully");
            response.put("timestamp", System.currentTimeMillis());
            
            log.info("Successfully reloaded presentation definition configuration");
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to reload configuration", e);
            
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to reload configuration");
            errorResponse.put("message", e.getMessage());
            
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }
}

package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadataDTO;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.JwksService;
import io.mosip.certify.core.spi.VCIssuanceService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class WellKnownController {

    private final CredentialConfigurationService credentialConfigurationService;

    private final VCIssuanceService vcIssuanceService;

    private final JwksService jwksService;

    public WellKnownController(CredentialConfigurationService credentialConfigurationService,
                               VCIssuanceService vcIssuanceService,
                               JwksService jwksService) {
        this.credentialConfigurationService = credentialConfigurationService;
        this.vcIssuanceService = vcIssuanceService;
        this.jwksService = jwksService;
    }

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadataDTO getCredentialIssuerMetadata() {
        return credentialConfigurationService.fetchCredentialIssuerMetadata();
    }

    @GetMapping(value = "/.well-known/did.json", produces = "application/json")
    public Map<String, Object> getDIDDocument() {
        return vcIssuanceService.getDIDDocument();
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        try {
            Map<String, Object> response = jwksService.getJwks();

            if (response != null && response.containsKey("keys")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> jwkList = (List<Map<String, Object>>) response.get("keys");
                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("keys", Collections.emptyList());
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
            }

        } catch (Exception e) {
            // Return empty keys array per OAuth 2.0 spec - clients should handle this gracefully
            // Do NOT cache error responses - allow retries
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("keys", Collections.emptyList());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(errorResponse);
        }
    }
}
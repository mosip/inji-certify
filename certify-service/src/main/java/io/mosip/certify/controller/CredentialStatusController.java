package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.services.StatusListCredentialService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/credentials")
public class CredentialStatusController {

    private final StatusListCredentialService statusListCredentialService;

    private final CredentialStatusService credentialStatusService;

    public CredentialStatusController(StatusListCredentialService statusListCredentialService,
                                      CredentialStatusService credentialStatusService) {
        this.statusListCredentialService = statusListCredentialService;
        this.credentialStatusService = credentialStatusService;
    }

    /**
     * Get Status List Credential by ID with optional fragment support
     * Handles URLs like: /{id} or /{id}#{fragment}
     *
     * @param id The status list credential ID
    //     * @param fragment Optional fragment identifier (for specific index references)
     * @return Status List VC JSON document
     * @throws CertifyException
     */
    @GetMapping(value = "/status-list/{id}", produces = "application/json")
    public String getStatusListById(@PathVariable("id") String id) throws CertifyException {

        log.debug("Retrieving status list credential with ID: {}", id);
        return statusListCredentialService.getStatusListCredential(id);
    }

    @PostMapping(value = "/status", produces = "application/json")
    public ResponseEntity<CredentialStatusResponse> updateCredential(
            @Valid @RequestBody UpdateCredentialStatusRequest updateCredentialStatusRequest) {
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(updateCredentialStatusRequest);
        if (result == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(result);
    }
}
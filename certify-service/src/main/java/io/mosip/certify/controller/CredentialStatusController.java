/*More actions
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequest;
import io.mosip.certify.core.dto.UpdateCredentialStatusRequestV2;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.CredentialStatusService;
import io.mosip.certify.services.StatusListCredentialService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/credentials")
public class CredentialStatusController {

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Autowired
    private CredentialStatusService credentialStatusService;

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

    @PostMapping("/status")
    public ResponseEntity<CredentialStatusResponse> updateCredential(
            @Valid @RequestBody UpdateCredentialStatusRequest updateCredentialStatusRequest) {
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatus(updateCredentialStatusRequest);
        if (result == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(result);
    }

    @PostMapping("/v2/status")
    public ResponseEntity<CredentialStatusResponse> updateCredentialV2(
            @Valid @RequestBody UpdateCredentialStatusRequestV2 updateCredentialStatusRequestV2) {
        CredentialStatusResponse result = credentialStatusService.updateCredentialStatusV2(updateCredentialStatusRequestV2);
        if (result == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(result);
    }
}
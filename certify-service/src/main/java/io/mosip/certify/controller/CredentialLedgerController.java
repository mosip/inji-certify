package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.core.dto.CredentialStatusResponse;
import io.mosip.certify.core.spi.CredentialLedgerService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/ledger-search")
public class CredentialLedgerController {

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @PostMapping()
    public ResponseEntity<List<CredentialStatusResponse>> searchCredentials(
            @Valid @RequestBody CredentialLedgerSearchRequest request) {
        List<CredentialStatusResponse> result = credentialLedgerService.searchCredentialLedger(request);
        if (result.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(result);
    }
}

package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialConfigurationRequest;
import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialIssuerMetadata;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/credentials/configurations")
public class CredentialConfigController {

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @PostMapping(produces = "application/json")
    public Map<String, String> addCredentialConfiguration(@Valid @RequestBody CredentialConfigurationRequest credentialConfigurationRequest) {
        return credentialConfigurationService.addCredentialConfiguration(credentialConfigurationRequest);
    }

    @GetMapping(value = "/{configurationId}", produces = "application/json")
    public CredentialConfigurationRequest getCredentialConfigurationById(@PathVariable String configurationId) {
        return credentialConfigurationService.getCredentialConfigurationById(configurationId);
    }

    @PutMapping(value = "/{configurationId}", produces = "application/json")
    public Map<String, String> updateCredentialConfiguration(@PathVariable String configurationId,
                                                             @Valid @RequestBody CredentialConfigurationRequest credentialConfigurationRequest) {
        return credentialConfigurationService.updateCredentialConfiguration(configurationId, credentialConfigurationRequest);
    }

    @DeleteMapping(value = "/{configurationId}", produces = "application/json")
    public void deleteCredentialConfigurationById(@PathVariable String configurationId) {
        credentialConfigurationService.deleteCredentialConfigurationById(configurationId);
    }
}

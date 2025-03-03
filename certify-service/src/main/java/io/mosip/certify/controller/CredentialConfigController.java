package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialConfigurationRequest;
import io.mosip.certify.core.dto.CredentialConfigurationSupported;
import io.mosip.certify.core.dto.CredentialIssuerMetadata;
import io.mosip.certify.core.spi.VCIssuanceService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/config")
public class CredentialConfigController {

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @PostMapping(value = "/credentials/configurations", produces = "application/json")
    public Map<String, String> getCredentialConfiguration(@Valid @RequestBody CredentialConfigurationRequest credentialConfigurationRequest) {
        return vcIssuanceService.addCredentialConfiguration(credentialConfigurationRequest);
    }

    @GetMapping(value = "/.well-known/openid-credential-issuer",produces = "application/json")
    public CredentialIssuerMetadata getMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return vcIssuanceService.fetchCredentialIssuerMetadata(version);
    }
}

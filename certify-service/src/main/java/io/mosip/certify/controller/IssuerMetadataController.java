package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialIssuerMetadata;
import io.mosip.certify.core.spi.VCIssuanceService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/issuer-metadata")
public class IssuerMetadataController {

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = "application/json")
    public CredentialIssuerMetadata getCredentialIssuerMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return vcIssuanceService.fetchCredentialIssuerMetadata(version);
    }
}

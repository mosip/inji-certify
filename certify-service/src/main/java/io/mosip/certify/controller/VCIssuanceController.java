package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.VCIssuanceService;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/issuance")
public class VCIssuanceController {

    private final VCIssuanceService vcIssuanceService;

    private final MessageSource messageSource;

    public VCIssuanceController(VCIssuanceService vcIssuanceService,
                                MessageSource messageSource) {
        this.vcIssuanceService = vcIssuanceService;
        this.messageSource = messageSource;
    }

    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/credential",produces = "application/json")
    public CredentialResponse getCredential(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        log.info("Get credential request received for credential configuration id: {}", credentialRequest.getCredentialConfigId());
        return vcIssuanceService.getCredential(credentialRequest);
    }
}
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.inji.certify.controller;

import io.inji.certify.core.dto.CredentialRequest;
import io.inji.certify.core.dto.CredentialResponse;
import io.inji.certify.core.dto.VCError;
import io.inji.certify.core.exception.CertifyException;
import io.inji.certify.core.spi.VCIssuanceService;
import io.inji.certify.exception.InvalidNonceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.Locale;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/issuance")
public class VCIssuanceController {

    @Autowired
    private VCIssuanceService vcIssuanceService;

    @Autowired
    MessageSource messageSource;

    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/credential",produces = "application/json")
    public CredentialResponse getCredential(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        return vcIssuanceService.getCredential(credentialRequest);
    }


    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd12/credential",produces = "application/json")
    public CredentialResponse getCredentialV12Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }


    /**
     * 1. The credential Endpoint MUST accept Access Tokens
     * @param credentialRequest VC credential request
     * @return Credential Response w.r.t requested format
     * @throws CertifyException
     */
    @PostMapping(value = "/vd11/credential",produces = "application/json")
    public CredentialResponse getCredentialV11Draft(@Valid @RequestBody CredentialRequest credentialRequest) throws CertifyException {
        CredentialResponse credentialResponse = vcIssuanceService.getCredential(credentialRequest);
        credentialResponse.setFormat(credentialRequest.getFormat());
        return credentialResponse;
    }
    /**
     * Open endpoint to provide VC issuer's metadata
     * @return
     */
    @GetMapping(value = "/.well-known/openid-credential-issuer",produces = "application/json")
    public Map<String, Object> getMetadata(
            @RequestParam(name = "version", required = false, defaultValue = "latest") String version) {
        return vcIssuanceService.getCredentialIssuerMetadata(version);
    }


    @ResponseBody
    @ExceptionHandler(InvalidNonceException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public VCError invalidNonceExceptionHandler(InvalidNonceException ex) {
        VCError vcError = new VCError();
        vcError.setError(ex.getErrorCode());
        vcError.setError_description(messageSource.getMessage(ex.getErrorCode(), null, ex.getErrorCode(), Locale.getDefault()));
        vcError.setC_nonce(ex.getClientNonce());
        vcError.setC_nonce_expires_in(ex.getClientNonceExpireSeconds());
        return vcError;
    }
}

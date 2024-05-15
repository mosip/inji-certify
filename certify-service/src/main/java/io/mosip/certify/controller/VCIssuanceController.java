package io.mosip.certify.controller;

import io.mosip.certify.core.dto.vci.CredentialRequest;
import io.mosip.certify.core.dto.vci.CredentialResponse;
import io.mosip.certify.core.dto.vci.VCError;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.vci.exception.InvalidNonceException;
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
@RequestMapping("/vci")
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

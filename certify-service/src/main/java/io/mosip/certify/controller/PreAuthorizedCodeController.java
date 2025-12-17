package io.mosip.certify.controller;

import io.mosip.certify.core.dto.*;
import io.mosip.certify.services.PreAuthorizedCodeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@Tag(name = "Pre-Authorized Code API", description = "Endpoints for Pre-Authorized Code Flow")
public class PreAuthorizedCodeController {

    @Autowired
    private PreAuthorizedCodeService preAuthorizedCodeService;

    @PostMapping(value = "/pre-authorized-data", produces = "application/json")
    public PreAuthorizedResponse generatePreAuthorizedCode(@Valid @RequestBody PreAuthorizedRequest request) {

        String credentialOfferUri = preAuthorizedCodeService.generatePreAuthorizedCode(request);
        PreAuthorizedResponse preAuthorizedResponse = new PreAuthorizedResponse();
        preAuthorizedResponse.setCredentialOfferUri(credentialOfferUri);
        return preAuthorizedResponse;
    }

    @GetMapping(value = "/credential-offer-data/{offer_id:.+}", produces = "application/json")
    public CredentialOfferResponse getCredentialOffer(@PathVariable("offer_id") String offerId) {
        return preAuthorizedCodeService.getCredentialOffer(offerId);
    }

    @PostMapping(value = "/token", consumes = "application/x-www-form-urlencoded", produces = "application/json")
    public TokenResponse token(
            @RequestParam("grant_type") String grantType,
            @RequestParam("pre-authorized_code") String preAuthorizedCode,
            @RequestParam(value = "tx_code", required = false) String txCode) {
        TokenRequest request = new TokenRequest(grantType, preAuthorizedCode, txCode);
        return preAuthorizedCodeService.exchangePreAuthorizedCode(request);
    }
}

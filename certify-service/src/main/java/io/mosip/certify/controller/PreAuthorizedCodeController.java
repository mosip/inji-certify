package io.mosip.certify.controller;

import io.mosip.certify.core.dto.CredentialOfferResponse;
import io.mosip.certify.core.dto.PreAuthorizedRequest;
import io.mosip.certify.core.dto.PreAuthorizedResponse;
import io.mosip.certify.services.PreAuthorizedCodeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

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
}

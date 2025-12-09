package io.mosip.certify.controller;

import io.mosip.certify.core.dto.PreAuthorizedRequest;
import io.mosip.certify.core.dto.PreAuthorizedResponse;
import io.mosip.certify.services.PreAuthorizedCodeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
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

}
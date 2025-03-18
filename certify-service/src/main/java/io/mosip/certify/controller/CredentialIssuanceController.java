package io.mosip.certify.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.mosip.certify.core.dto.CredentialIssuanceDTO;
import io.mosip.certify.core.dto.CredentialIssuanceResponseDTO;
import io.mosip.certify.services.CredentialIssuanceService;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/v1/credentials")
@Tag(name = "Credential Issuance", description = "APIs for credential issuance")
public class CredentialIssuanceController {

    @Autowired
    private CredentialIssuanceService credentialIssuanceService;
    
    @PostMapping(
        path = "/issue-credential",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(summary = "Issue a new credential", description = "Issues a new verifiable credential with status tracking capabilities")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Credential successfully issued", 
                    content = @Content(schema = @Schema(implementation = ResponseWrapper.class))),
        @ApiResponse(responseCode = "400", description = "Invalid input parameters"),
        @ApiResponse(responseCode = "500", description = "Internal server error occurred")
    })
    public ResponseEntity<ResponseWrapper<CredentialIssuanceResponseDTO>> issueCredential(
            @Valid @RequestBody CredentialIssuanceDTO issuanceDTO) {
        
        ResponseWrapper<CredentialIssuanceResponseDTO> response = credentialIssuanceService.issueCredential(issuanceDTO);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
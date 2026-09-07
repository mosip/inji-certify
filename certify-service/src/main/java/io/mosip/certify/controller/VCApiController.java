package io.mosip.certify.controller;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.VCApiIssueRequest;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.services.VCApiIssuanceService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/vc-api")
@Tag(name = "W3C VC API", description = "Endpoints for W3C Verifiable Credentials API issuance")
@ConditionalOnProperty(value = "mosip.certify.vc-api.enabled", havingValue = "true")
public class VCApiController {

    public static final String CREDENTIAL_CONFIGURATION_ID_HEADER = "X-Credential-Configuration-Id";

    @Autowired
    private VCApiIssuanceService vcApiIssuanceService;

    @PostMapping(value = "/credentials/issue", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> issueCredential(
            @RequestHeader(value = CREDENTIAL_CONFIGURATION_ID_HEADER) String credentialConfigurationId,
            @Valid @RequestBody VCApiIssueRequest request) {
        if (StringUtils.isBlank(credentialConfigurationId)) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }
        log.info("VC API credentials/issue for configuration: {}", credentialConfigurationId.trim());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(vcApiIssuanceService.issue(request, credentialConfigurationId.trim()));
    }
}

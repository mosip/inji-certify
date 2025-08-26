/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.IarConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.spi.IarService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Interactive Authorization Request (IAR) Service Implementation
 * Handles authorization requests for OpenID4VCI credential issuance
 * 
 * Initially uses hardcoded OpenID4VP requests. Will be replaced with 
 * verify service integration once verify branch is ready.
 */
@Slf4j
@Service
public class IarServiceImpl implements IarService {

    @Value("${mosip.certify.iar.default-client-id:default-wallet-client}")
    private String defaultClientId;

    @Value("${mosip.certify.iar.session-timeout-seconds:1800}")
    private int sessionTimeoutSeconds;

    @Value("${mosip.certify.iar.require-interaction:true}")
    private boolean requireInteractionByDefault;

    @Value("${mosip.certify.iar.presentation.default-id:employment-check}")
    private String defaultPresentationId;

    @Value("${mosip.certify.iar.presentation.identity-descriptor-id:identity}")
    private String identityDescriptorId;

    @Value("${mosip.certify.iar.presentation.contract-descriptor-id:contract}")
    private String contractDescriptorId;

    @Value("${mosip.certify.iar.presentation.fields.given-name:$.credentialSubject.given_name}")
    private String givenNamePath;

    @Value("${mosip.certify.iar.presentation.fields.family-name:$.credentialSubject.family_name}")
    private String familyNamePath;

    @Value("${mosip.certify.iar.presentation.fields.contract-id:$.credentialSubject.contract_id}")
    private String contractIdPath;

    @Value("${mosip.certify.iar.openid4vp.response-type:vp_token}")
    private String openid4vpResponseType;

    @Value("${mosip.certify.iar.openid4vp.response-mode:iar-post.jwt}")
    private String openid4vpResponseMode;

    @Override
    public IarResponse processAuthorizationRequest(IarRequest iarRequest) throws CertifyException {
        log.info("Processing IAR for client_id: {}, response_type: {}", 
                 iarRequest.getClientId(), iarRequest.getResponseType());

        try {
            // Validate the request
            validateIarRequest(iarRequest);

            // Generate auth session
            String authSession = generateAuthSession();

            // For now, always require interaction (hardcoded logic)
            // Later this will be replaced with business logic to determine
            // if presentation is actually needed based on client and credentials
            if (requireInteractionByDefault || shouldRequireInteraction(iarRequest)) {
                return generateOpenId4VpRequest(iarRequest, authSession);
            } else {
                // Direct authorization without interaction
                return createDirectAuthorizationResponse(authSession);
            }

        } catch (CertifyException e) {
            log.error("IAR processing failed for client: {}, error: {}", 
                      iarRequest.getClientId(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during IAR processing for client: {}", 
                      iarRequest.getClientId(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "IAR processing failed", e);
        }
    }

    @Override
    public String generateAuthSession() {
        String sessionId = IarConstants.AUTH_SESSION_PREFIX + UUID.randomUUID().toString().substring(0, 8);
        log.debug("Generated auth session: {}", sessionId);
        return sessionId;
    }

    @Override
    public void validateIarRequest(IarRequest iarRequest) throws CertifyException {
        log.debug("Validating IAR request for client: {}", iarRequest.getClientId());

        // Validate required fields
        if (!StringUtils.hasText(iarRequest.getResponseType())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getClientId())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getCodeChallenge())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getCodeChallengeMethod())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(iarRequest.getRedirectUri())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        // Validate response_type
        if (!IarConstants.RESPONSE_TYPE_CODE.equals(iarRequest.getResponseType())) {
            throw new CertifyException(IarConstants.UNSUPPORTED_RESPONSE_TYPE, 
                                     "Unsupported response_type: " + iarRequest.getResponseType());
        }

        // Validate code_challenge_method
        if (!IarConstants.CODE_CHALLENGE_METHOD_S256.equals(iarRequest.getCodeChallengeMethod()) &&
            !IarConstants.CODE_CHALLENGE_METHOD_PLAIN.equals(iarRequest.getCodeChallengeMethod())) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        log.debug("IAR request validation successful for client: {}", iarRequest.getClientId());
    }

    @Override
    public IarResponse generateOpenId4VpRequest(IarRequest iarRequest, String authSession) throws CertifyException {
        log.info("Generating OpenID4VP request for auth_session: {}", authSession);

        try {
            IarResponse response = new IarResponse();
            response.setStatus(IarConstants.STATUS_REQUIRE_INTERACTION);
            response.setType(IarConstants.TYPE_OPENID4VP_PRESENTATION);
            response.setAuthSession(authSession);

            // Create hardcoded OpenID4VP request
            OpenId4VpRequest openId4VpRequest = createOpenId4VpRequest(iarRequest);
            response.setOpenid4vpRequest(openId4VpRequest);

            log.info("OpenID4VP request generated successfully for auth_session: {}", authSession);
            return response;

        } catch (Exception e) {
            log.error("Failed to generate OpenID4VP request for auth_session: {}", authSession, e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate OpenID4VP request", e);
        }
    }

    /**
     * Creates hardcoded OpenID4VP request for testing
     * This will be replaced with verify service integration
     */
    private OpenId4VpRequest createOpenId4VpRequest(IarRequest iarRequest) {
        OpenId4VpRequest openId4VpRequest = new OpenId4VpRequest();
        openId4VpRequest.setResponseType(openid4vpResponseType);
        openId4VpRequest.setResponseMode(openid4vpResponseMode);
        openId4VpRequest.setClientId(iarRequest.getClientId());

        // Create configurable presentation definition
        PresentationDefinition presentationDefinition = createConfigurablePresentationDefinition();
        openId4VpRequest.setPresentationDefinition(presentationDefinition);

        return openId4VpRequest;
    }

    /**
     * Creates presentation definition using configurable properties
     */
    private PresentationDefinition createConfigurablePresentationDefinition() {
        PresentationDefinition presentationDefinition = new PresentationDefinition();
        presentationDefinition.setId(defaultPresentationId);

        // Create input descriptors
        List<InputDescriptor> inputDescriptors = Arrays.asList(
            createIdentityInputDescriptor(),
            createContractInputDescriptor()
        );
        presentationDefinition.setInputDescriptors(inputDescriptors);

        return presentationDefinition;
    }

    /**
     * Creates identity input descriptor for given_name and family_name using configurable paths
     */
    private InputDescriptor createIdentityInputDescriptor() {
        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId(identityDescriptorId);

        InputConstraints constraints = new InputConstraints();
        List<FieldConstraint> fields = Arrays.asList(
            createFieldConstraint(givenNamePath),
            createFieldConstraint(familyNamePath)
        );
        constraints.setFields(fields);
        inputDescriptor.setConstraints(constraints);

        return inputDescriptor;
    }

    /**
     * Creates contract input descriptor for contract_id using configurable path
     */
    private InputDescriptor createContractInputDescriptor() {
        InputDescriptor inputDescriptor = new InputDescriptor();
        inputDescriptor.setId(contractDescriptorId);

        InputConstraints constraints = new InputConstraints();
        List<FieldConstraint> fields = Arrays.asList(
            createFieldConstraint(contractIdPath)
        );
        constraints.setFields(fields);
        inputDescriptor.setConstraints(constraints);

        return inputDescriptor;
    }

    /**
     * Creates field constraint for the given JSON path
     */
    private FieldConstraint createFieldConstraint(String jsonPath) {
        FieldConstraint fieldConstraint = new FieldConstraint();
        fieldConstraint.setPath(Arrays.asList(jsonPath));
        return fieldConstraint;
    }

    /**
     * Determines if interaction should be required based on business logic
     * Currently hardcoded, will be replaced with actual business logic
     */
    private boolean shouldRequireInteraction(IarRequest iarRequest) {
        // Hardcoded logic - always require interaction for now
        // Later this will check:
        // - Client configuration
        // - Credential type being requested
        // - User authentication status
        // - Policy requirements
        return true;
    }

    /**
     * Creates direct authorization response when no interaction is needed
     */
    private IarResponse createDirectAuthorizationResponse(String authSession) {
        IarResponse response = new IarResponse();
        response.setStatus(IarConstants.STATUS_COMPLETE);
        response.setAuthSession(authSession);
        // No openid4vp_request needed for direct authorization
        return response;
    }

}

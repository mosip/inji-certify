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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import io.mosip.certify.entity.IarSession;
import io.mosip.certify.repository.IarSessionRepository;

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

    private static final String HARDCODED_AUTH_SESSION = "session-test1234";
    @Autowired
    private IarSessionRepository iarSessionRepository;

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

    @Value("${mosip.certify.iar.openid4vp.response-uri:http://localhost:8090/v1/certify/oauth/iar}")
    private String openid4vpResponseUri;

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
        // Return hardcoded auth_session for testing
        log.debug("Generated auth session: {}", HARDCODED_AUTH_SESSION);
        return HARDCODED_AUTH_SESSION;
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

            String transactionId = IarConstants.TRANSACTION_ID_PREFIX + UUID.randomUUID().toString().substring(0, 8);
            log.info("Generated transaction_id: {} for auth_session: {}", transactionId, authSession);
            IarSession iarSession = new IarSession();
            iarSession.setAuthSession(authSession);
            iarSession.setTransactionId(transactionId);
            iarSessionRepository.save(iarSession);
            return response;

        } catch (Exception e) {
            log.error("Failed to generate OpenID4VP request for auth_session: {}", authSession, e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "Failed to generate OpenID4VP request", e);
        }
    }
    

    @Override
    public IarPresentationResponse processVpPresentationResponse(IarPresentationRequest presentationRequest) throws CertifyException {
        log.info("Processing VP presentation for auth_session: {}", presentationRequest.getAuthSession());

        try {
            // Validate the presentation request
            validateIarPresentationRequest(presentationRequest);

            // Validate auth_session (step 14)
            if (!isValidAuthSession(presentationRequest.getAuthSession())) {
                log.warn("Invalid auth_session: {}", presentationRequest.getAuthSession());
                throw new InvalidRequestException(IarConstants.INVALID_AUTH_SESSION);
            }

            // Mock VP Verifier interaction (steps 15-17)
            // NOTE: This is intentionally hardcoded for now. When Verify service is available,
            //       replace this with an HTTP POST to the verifier's /oid4vp/response endpoint
            //       using response_uri from the openid4vp_request returned at step 9.
            boolean isVpValid = mockVerifyPresentation(presentationRequest.getOpenid4vpPresentation());

            IarPresentationResponse response = new IarPresentationResponse();
            if (isVpValid) {
                // Step 18: Successful verification (mocked)
                response.setStatus(IarConstants.STATUS_OK);
                response.setAuthorizationCode(generateAuthorizationCode());
                log.info("VP verification successful for auth_session: {}", presentationRequest.getAuthSession());
            } else {
                // Step 18: Failed verification (mocked)
                response.setStatus(IarConstants.STATUS_ERROR);
                response.setError(IarConstants.INVALID_REQUEST);
                response.setErrorDescription("VP verification failed");
                log.warn("VP verification failed for auth_session: {}", presentationRequest.getAuthSession());
            }

            return response;

        } catch (CertifyException e) {
            log.error("VP presentation processing failed for auth_session: {}, error: {}",
                      presentationRequest.getAuthSession(), e.getErrorCode(), e);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error during VP presentation processing for auth_session: {}",
                      presentationRequest.getAuthSession(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR, "VP presentation processing failed", e);
        }
    }

    /**
     * Validates the Verifiable Presentation request
     */
    private void validateIarPresentationRequest(IarPresentationRequest presentationRequest) throws CertifyException {
        log.debug("Validating VP presentation request for auth_session: {}", presentationRequest.getAuthSession());

        if (!StringUtils.hasText(presentationRequest.getAuthSession())) {
            throw new InvalidRequestException(IarConstants.INVALID_REQUEST);
        }

        if (!StringUtils.hasText(presentationRequest.getOpenid4vpPresentation())) {
            throw new InvalidRequestException(IarConstants.INVALID_REQUEST);
        }

        log.debug("VP presentation request validation successful for auth_session: {}", presentationRequest.getAuthSession());
    }

    /**
     * Validates auth_session using hardcoded value
     */
    private boolean isValidAuthSession(String authSession) {
        boolean isValid = iarSessionRepository.findByAuthSession(authSession).isPresent();
        log.debug("Validated auth_session: {}, result: {}", authSession, isValid);
        return isValid;
    }

    /**
     * Mock VP Verifier interaction
     * TODO: Replace with actual API call to VP Verifier's /oid4vp/response endpoint
     */
    private boolean mockVerifyPresentation(String openid4vpPresentation) {
        log.debug("Mock verifying VP presentation: {}", openid4vpPresentation);

        // Minimal check for response_mode
        if (openid4vpResponseMode.equals(IarConstants.RESPONSE_MODE_IAR_POST_JWT)) {
            log.debug("Mock decryption of iar-post.jwt presentation");
            return openid4vpPresentation.contains("response"); // Basic check for JWT structure
        } else if (openid4vpResponseMode.equals(IarConstants.RESPONSE_MODE_IAR_POST)) {
            log.debug("Processing unencrypted iar-post presentation");
            return openid4vpPresentation.contains("vp_token") && 
                   openid4vpPresentation.contains("presentation_submission");
        } else {
            log.warn("Unsupported response_mode: {}", openid4vpResponseMode);
            return false;
        }
    }

    /**
     * Generates an authorization code for successful VP verification
     */
    private String generateAuthorizationCode() {
        String authCode = IarConstants.AUTH_CODE_PREFIX + UUID.randomUUID().toString().substring(0, 8);
        log.debug("Generated authorization code: {}", authCode);
        return authCode;
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
        // response_uri indicates where the wallet must POST the VP response.
        // Configurable via mosip.certify.iar.openid4vp.response-uri
        openId4VpRequest.setResponseUri(openid4vpResponseUri);

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

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.VCIExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.VCIssuancePlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.CredentialMetadata;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.VCIssuanceUtil;
import io.mosip.certify.validators.CredentialRequestValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

import static io.mosip.certify.utils.VCIssuanceUtil.validateLdpVcFormatRequest;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "VCIssuance")
public class VCIssuanceServiceImpl implements VCIssuanceService {

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCIssuancePlugin vcIssuancePlugin;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        boolean isValidCredentialRequest = CredentialRequestValidator.isValid(credentialRequest);
        if(!isValidCredentialRequest) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();

        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialMetadata credentialMetadata = null;
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialMetadata> result = VCIssuanceUtil.getScopeCredentialMapping(scope, credentialRequest.getFormat(), credentialConfigurationService.fetchCredentialIssuerMetadata("latest"), credentialRequest);
            if(result.isPresent()) {
                credentialMetadata = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        ProofValidator proofValidator = proofValidatorFactory.getProofValidator(credentialRequest.getProof().getProof_type());
        String validCNonce = VCIssuanceUtil.getValidClientNonce(vciCacheService, parsedAccessToken, cNonceExpireSeconds, securityHelperService, log);
        if(!proofValidator.validate((String)parsedAccessToken.getClaims().get(Constants.CLIENT_ID), validCNonce,
                credentialRequest.getProof(), credentialMetadata.getProofTypesSupported())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        //Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialRequest.getFormat(), vcResult);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE);
    }

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata,
                                                String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());


        VCResult<?> vcResult = null;
        try {
            switch (credentialRequest.getFormat()) {
                case "ldp_vc" :
                    vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                    vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                    vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                    validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                    vcResult = vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;

                // jwt_vc_json & jwt_vc_json-ld cases are merged
                case "jwt_vc_json-ld" :
                case "jwt_vc_json" :
                    vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                    vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                    vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                    vcResult = vcIssuancePlugin.getVerifiableCredential(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                case VCFormats.MSO_MDOC :
                    vcRequestDto.setClaims(credentialRequest.getClaims());
                    vcRequestDto.setDoctype( credentialRequest.getDoctype());
                    vcResult = vcIssuancePlugin.getVerifiableCredential(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                default:
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
            }
        } catch (VCIExchangeException e) {
            throw new CertifyException(e.getErrorCode());
        }

        if(vcResult != null && vcResult.getCredential() != null)
            return vcResult;

        log.error("Failed to generate VC : {}", vcResult);
        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.ERROR,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
    }

}
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
import io.mosip.certify.core.constants.VCIErrorConstants;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.VCIssuanceUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "VCIssuance")
public class VCIssuanceServiceImpl implements VCIssuanceService {

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCIssuancePlugin vcIssuancePlugin;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        List<VCResult<?>> vcResults = new ArrayList<>();

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();

        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialConfigurationSupported credentialConfigurationSupported = null;
        CredentialIssuerMetadataDTO credentialIssuerMetadataDTO = credentialConfigurationService.fetchCredentialIssuerMetadata();

        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialConfigurationSupported> result = VCIssuanceUtil.getScopeCredentialMapping(
                    scope,credentialRequest.getCredentialConfigId() , credentialIssuerMetadataDTO);
            if(result.isPresent()) {
                credentialConfigurationSupported = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialConfigurationSupported == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(VCIErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        String clientId = (String) parsedAccessToken.getClaims().get(Constants.CLIENT_ID);
        String accessTokenHash = parsedAccessToken.getAccessTokenHash();
        Map<String, Object> supportedProofTypes = credentialConfigurationSupported.getProofTypesSupported();
        Map<ProofType, Set<String>> proofs = credentialRequest.getProofs()
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue() == null
                                ? Collections.emptySet()
                                : new LinkedHashSet<>(entry.getValue()),
                        (a, b) -> a,
                        LinkedHashMap::new
                ));
        List<String> holderIds = new ArrayList<>();
        String nonceEndpoint = credentialIssuerMetadataDTO.getNonceEndpoint();
        for (Map.Entry<ProofType,Set<String>> entry : proofs.entrySet()) {
            String proofType = entry.getKey().toString().toLowerCase();
            ProofValidator proofValidator = proofValidatorFactory.getProofValidator(proofType);
            for (String proofValue : entry.getValue()) {
                try {
                    String validCNonce = VCIssuanceUtil.validateAndGetClientNonce(vciCacheService, proofValue, log, nonceEndpoint);

                    boolean isValid = proofValidator.validate(clientId, validCNonce, proofValue, supportedProofTypes);
                    if (!isValid) {
                        continue;
                    }
                    if (validCNonce != null) {
                        auditWrapper.logAudit(Action.NONCE_VALIDATION, ActionStatus.SUCCESS,
                                AuditHelper.buildAuditDto(validCNonce, "cNonce"), null);
                    }
                    String keyMaterial = proofValidator.getKeyMaterial(proofValue);
                    if (keyMaterial != null) {
                        holderIds.add(keyMaterial);
                    }
                } catch (CertifyException e) {
                    auditWrapper.logAudit(Action.PROOF_VALIDATION, ActionStatus.ERROR,
                            AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), e);
                    throw e;
                }
            }
        }

        if(holderIds.isEmpty()) {
            throw new CertifyException(VCIErrorConstants.INVALID_PROOF, "None of the submitted proofs passed validation.");
        }

        for (String holderId : holderIds) {
            vcResults.add(getVerifiableCredential(credentialConfigurationSupported, holderId));
        }

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialConfigurationSupported.getFormat(), vcResults);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        throw new InvalidRequestException(ErrorConstants.UNSUPPORTED_IN_CURRENT_PLUGIN_MODE);
    }

    private VCResult<?> getVerifiableCredential(CredentialConfigurationSupported credentialConfigurationSupported,
                                                String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialConfigurationSupported.getFormat());


        VCResult<?> vcResult = null;
        try {
            switch (credentialConfigurationSupported.getFormat()) {
                case VCFormats.LDP_VC :
                    vcRequestDto.setContext(credentialConfigurationSupported.getContext());
                    vcRequestDto.setType(credentialConfigurationSupported.getTypes());
                    vcResult = vcIssuancePlugin.getVerifiableCredentialWithLinkedDataProof(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                case VCFormats.MSO_MDOC :
                    vcRequestDto.setDoctype( credentialConfigurationSupported.getDocType());
                    vcResult = vcIssuancePlugin.getVerifiableCredential(vcRequestDto, holderId,
                            parsedAccessToken.getClaims());
                    break;
                default:
                    throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, "Invalid or unsupported VC format requested.");
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
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import foundation.identity.jsonld.JsonLDObject;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.config.IndexedAttributesConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.SignatureAlg;
import io.mosip.certify.core.constants.VCDM2Constants;
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
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.entity.Ledger;
import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.enums.CredentialFormat;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.repository.CredentialStatusTransactionRepository;
import io.mosip.certify.repository.LedgerRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.utils.VCIssuanceUtil;
import io.mosip.certify.validators.CredentialRequestValidator;
import io.mosip.certify.vcformatters.VCFormatter;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.OffsetDateTime;
import java.util.*;

import static io.mosip.certify.utils.VCIssuanceUtil.getScopeCredentialMapping;
import static io.mosip.certify.utils.VCIssuanceUtil.validateLdpVcFormatRequest;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

    public static final Map<String, List<String>> keyChooser = Map.of(
            SignatureAlg.RSA_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_RSA, Constants.EMPTY_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2018, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.ED25519_SIGNATURE_SUITE_2020, List.of(Constants.CERTIFY_VC_SIGN_ED25519, Constants.ED25519_REF_ID),
            SignatureAlg.EC_K1_2016, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN),
            SignatureAlg.EC_SECP256K1_2019, List.of(Constants.CERTIFY_VC_SIGN_EC_K1, Constants.EC_SECP256K1_SIGN),
            SignatureAlg.EC_SECP256R1_2019, List.of(Constants.CERTIFY_VC_SIGN_EC_R1, Constants.EC_SECP256R1_SIGN));

    @Value("${mosip.certify.cnonce-expire-seconds:300}")
    private int cNonceExpireSeconds;

    @Autowired
    private ParsedAccessToken parsedAccessToken;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private CredentialFactory credentialFactory;

    @Autowired
    private DataProviderPlugin dataProviderPlugin;

    @Value("${mosip.certify.data-provider-plugin.did-url}")
    private String didUrl;

    @Value("${mosip.certify.data-provider-plugin.rendering-template-id:}")
    private String renderTemplateId;

    @Autowired
    private ProofValidatorFactory proofValidatorFactory;

    @Autowired
    private VCICacheService vciCacheService;

    @Autowired
    private SecurityHelperService securityHelperService;

    @Autowired
    private AuditPlugin auditWrapper;

    private Map<String, Object> didDocument;

    @Autowired
    private CredentialConfigurationService credentialConfigurationService;

    @Value("${mosip.certify.identifier}")
    private String certifyIssuer;

    @Autowired
    private StatusListCredentialService statusListCredentialService;

    @Value("${mosip.certify.domain.url}")
    private String domainUrl;

    @Autowired
    private DIDDocumentUtil didDocumentUtil;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        // 1. Credential Request validation
        boolean isValidCredentialRequest = CredentialRequestValidator.isValid(credentialRequest);
        if(!isValidCredentialRequest) {
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST);
        }

        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();
        // 2. Scope Validation
        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialMetadata credentialMetadata = null;
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialMetadata> result = getScopeCredentialMapping(scope, credentialRequest.getFormat(), credentialConfigurationService.fetchCredentialIssuerMetadata("latest"), credentialRequest);
            if(result.isPresent()) {
                credentialMetadata = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialMetadata == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(ErrorConstants.INVALID_SCOPE);
        }

        // 3. Proof Validation
        ProofValidator proofValidator = proofValidatorFactory.getProofValidator(credentialRequest.getProof().getProof_type());
        String validCNonce = VCIssuanceUtil.getValidClientNonce(vciCacheService, parsedAccessToken, cNonceExpireSeconds, securityHelperService, log);
        proofValidator.validateCNonce(validCNonce, cNonceExpireSeconds, parsedAccessToken, credentialRequest);
        if(!proofValidator.validate((String)parsedAccessToken.getClaims().get(Constants.CLIENT_ID), validCNonce,
                credentialRequest.getProof(), credentialMetadata.getProofTypesSupported())) {
            throw new CertifyException(ErrorConstants.INVALID_PROOF);
        }

        // 4. Get VC from configured plugin implementation
        VCResult<?> vcResult = getVerifiableCredential(credentialRequest, credentialMetadata,
                proofValidator.getKeyMaterial(credentialRequest.getProof()));

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(parsedAccessToken.getAccessTokenHash(), "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialRequest.getFormat(), vcResult);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        didDocument = didDocumentUtil.generateDIDDocument(didUrl);
        return didDocument;
    }

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata,String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());

        switch (credentialRequest.getFormat()) {
            case "ldp_vc" :
                VCResult<JsonLDObject> VC = new VCResult<>();
                vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    String templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.TEMPLATE_NAME, templateName);
                    templateParams.put(Constants.DID_URL, didUrl);
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    jsonObject.put(Constants.TYPE, credentialRequest.getCredential_definition().getType());
                    List<String> credentialStatusPurposeList = vcFormatter.getCredentialStatusPurpose(templateName);
                    if (credentialStatusPurposeList != null && !credentialStatusPurposeList.isEmpty()) {
                        statusListCredentialService.addCredentialStatus(jsonObject, credentialStatusPurposeList.getFirst());
                    }
                    jsonObject.put("_holderId", holderId);
                    Credential cred = credentialFactory.getCredential(credentialRequest.getFormat()).orElseThrow(()-> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));
                    templateParams.putAll(jsonObject.toMap());
                    String unsignedCredential=cred.createCredential(templateParams, templateName);
                    jsonObject.remove(VCDM2Constants.CREDENTIAL_STATUS);
                    return cred.addProof(unsignedCredential,"", vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName),vcFormatter.getDidUrl(templateName), vcFormatter.getSignatureCryptoSuite(templateName));
                } catch(DataProviderExchangeException e) {
                    throw new CertifyException(e.getErrorCode());
                } catch (JSONException e) {
                    log.error(e.getMessage(), e);
                    throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
                }
                case "vc+sd-jwt":
                vcRequestDto.setVct(credentialRequest.getVct());
                try {
                    // TODO(multitenancy): later decide which plugin out of n plugins is the correct one
                    JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
                    Map<String, Object> templateParams = new HashMap<>();
                    String templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.TEMPLATE_NAME, templateName);
                    templateParams.put(Constants.DID_URL, didUrl);
                    if (!StringUtils.isEmpty(renderTemplateId)) {
                        templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
                    }
                    Credential cred = credentialFactory.getCredential(CredentialFormat.VC_SD_JWT.toString()).orElseThrow(()-> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));
                    jsonObject.put("_holderId", holderId);
                    templateParams.putAll(jsonObject.toMap());
                    templateParams.put(Constants.VCTYPE, vcRequestDto.getVct());
                    // This is with reference to the Representation of a Key ID for a Proof-of-Possession Key
                    // Ref: https://datatracker.ietf.org/doc/html/rfc7800#section-3.4
                    templateParams.put(Constants.CONFIRMATION, Map.of("kid", holderId));
                    templateParams.put(Constants.ISSUER, certifyIssuer);
                    String unsignedCredential=cred.createCredential(templateParams, templateName);
                    return cred.addProof(unsignedCredential,"", vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName),vcFormatter.getDidUrl(templateName), vcFormatter.getSignatureCryptoSuite(templateName));
                } catch(DataProviderExchangeException e) {
                    log.error("Error processing the SD-JWT :", e);
                    throw new CertifyException(ErrorConstants.VC_ISSUANCE_FAILED);
                }
                default:
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
            }
    }
}

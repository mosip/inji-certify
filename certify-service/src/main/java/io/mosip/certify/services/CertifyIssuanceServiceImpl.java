/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.CredentialMetadata;
import io.mosip.certify.core.dto.CredentialRequest;
import io.mosip.certify.core.dto.CredentialResponse;
import io.mosip.certify.core.dto.ParsedAccessToken;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.InvalidRequestException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.core.util.SecurityHelperService;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.core.dto.CredentialStatusDetail;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.utils.VCIssuanceUtil;
import io.mosip.certify.validators.CredentialRequestValidator;
import io.mosip.certify.vcformatters.VCFormatter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.*;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;

import static io.mosip.certify.utils.VCIssuanceUtil.getScopeCredentialMapping;
import static io.mosip.certify.utils.VCIssuanceUtil.validateLdpVcFormatRequest;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

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

    @Autowired
    private LedgerUtils ledgerUtils;

    @Autowired
    private CredentialLedgerService credentialLedgerService;

    @Value("#{${mosip.certify.issuer.ledger-enabled:true}}")
    private boolean isLedgerEnabled;

    @Value("${mosip.certify.data-provider-plugin.id-field-prefix-uri:}")
    String idPrefix;

    @Value("${mosip.certify.data-provider-plugin.vc-expiry-duration:P730D}")
    String defaultExpiryDuration;

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

    private VCResult<?> getVerifiableCredential(CredentialRequest credentialRequest, CredentialMetadata credentialMetadata, String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialRequest.getFormat());

        try {
            // Fetch data once, as it's common to all formats
            JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());

            String templateName;
            Map<String, Object> templateParams = new HashMap<>();
            String format = credentialRequest.getFormat();

            // Handle format-specific setup
            switch (format) {
                case "ldp_vc":
                    vcRequestDto.setContext(credentialRequest.getCredential_definition().getContext());
                    vcRequestDto.setType(credentialRequest.getCredential_definition().getType());
                    vcRequestDto.setCredentialSubject(credentialRequest.getCredential_definition().getCredentialSubject());
                    validateLdpVcFormatRequest(credentialRequest, credentialMetadata);
                    templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    jsonObject.put(Constants.TYPE, credentialRequest.getCredential_definition().getType());

                    List<String> credentialStatusPurposeList = vcFormatter.getCredentialStatusPurpose(templateName);
                    if (credentialStatusPurposeList != null && !credentialStatusPurposeList.isEmpty() && credentialRequest.getCredential_definition().getContext().contains(VCDM2Constants.URL)) {
                        if(!isLedgerEnabled) {
                            log.warn("Ledger feature is currently disabled. Since revocation is enabled, please note that searching for VCs to revoke within Certify is not available.");
                        }
                        statusListCredentialService.addCredentialStatus(jsonObject, credentialStatusPurposeList.getFirst());
                    }
                    break;

                case "vc+sd-jwt":
                    vcRequestDto.setVct(credentialRequest.getVct());
                    templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.VCTYPE, vcRequestDto.getVct());
                    templateParams.put(Constants.CONFIRMATION, Map.of("kid", holderId));
                    templateParams.put(Constants.ISSUER, certifyIssuer);
                    jsonObject.put(Constants.TYPE, vcRequestDto.getVct());
                    break;

                default:
                    throw new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT);
            }

            // Common logic for all formats
            templateParams.put(Constants.TEMPLATE_NAME, templateName);
            templateParams.put(Constants.DID_URL, didUrl);
            if (!StringUtils.isEmpty(renderTemplateId)) {
                templateParams.put(Constants.RENDERING_TEMPLATE_ID, renderTemplateId);
            }
            jsonObject.put("_holderId", holderId);
            templateParams.putAll(jsonObject.toMap());
            if(!StringUtils.isEmpty(idPrefix)) {
                templateParams.put(VCDMConstants.CREDENTIAL_ID, idPrefix + UUID.randomUUID());
            }
            ZonedDateTime zonedDateTime = ZonedDateTime.now(ZoneOffset.UTC);
            // current time
            String time = zonedDateTime.format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            Duration duration;
            try {
                duration = Duration.parse(defaultExpiryDuration);
            } catch (DateTimeParseException e) {
                log.warn("Incorrect expiry duration format in properties: {}. Using default P730D ~ 2Y", defaultExpiryDuration);
                duration = Duration.parse("P730D");
            }
            String expiryTime = zonedDateTime.plus(duration).format(DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
            templateParams.put(VCDM2Constants.VALID_FROM, time);
            templateParams.put(VCDM2Constants.VALID_UNTIL, expiryTime);

            Credential cred = credentialFactory.getCredential(format).orElseThrow(() -> new CertifyException(ErrorConstants.UNSUPPORTED_VC_FORMAT));
            String unsignedCredential = cred.createCredential(templateParams, templateName);
            if(isLedgerEnabled) {
                Map<String, Object> indexedAttributes = ledgerUtils.extractIndexedAttributes(jsonObject);
                String credentialType = LedgerUtils.extractCredentialType(jsonObject);
                String credentialId = null;
                if(templateParams.containsKey(VCDMConstants.CREDENTIAL_ID)) {
                    credentialId = templateParams.get(VCDMConstants.CREDENTIAL_ID).toString();
                }
                CredentialStatusDetail credentialStatusDetail = ledgerUtils.extractCredentialStatusDetails(jsonObject);
                LocalDateTime issuanceDate = LocalDateTime.parse(time, DateTimeFormatter.ofPattern(Constants.UTC_DATETIME_PATTERN));
                credentialLedgerService.storeLedgerEntry(credentialId, didUrl, credentialType, credentialStatusDetail, indexedAttributes, issuanceDate);
                log.info("Successfully stored the credential issuance data in ledger with credentialType: {}", credentialType);
            }
            VCResult<?> result = cred.addProof(unsignedCredential, "", vcFormatter.getProofAlgorithm(templateName), vcFormatter.getAppID(templateName), vcFormatter.getRefID(templateName), vcFormatter.getDidUrl(templateName), vcFormatter.getSignatureCryptoSuite(templateName));

            jsonObject.remove(VCDM2Constants.CREDENTIAL_STATUS);
            return result;

        } catch (DataProviderExchangeException e) {
            throw new CertifyException(e.getErrorCode());
        } catch (JSONException e) {
            log.error(e.getMessage(), e);
            throw new CertifyException(ErrorConstants.UNKNOWN_ERROR);
        }
    }
}

/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.api.dto.VCResult;
import io.mosip.certify.api.exception.DataProviderExchangeException;
import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.api.spi.DataProviderPlugin;
import io.mosip.certify.api.util.Action;
import io.mosip.certify.api.util.ActionStatus;
import io.mosip.certify.api.util.AuditHelper;
import io.mosip.certify.config.VelocityEnvConfig;
import io.mosip.certify.core.constants.*;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.NotAuthenticatedException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.core.spi.CredentialLedgerService;
import io.mosip.certify.core.spi.VCIssuanceService;
import io.mosip.certify.credential.Credential;
import io.mosip.certify.credential.CredentialFactory;
import io.mosip.certify.proof.ProofValidator;
import io.mosip.certify.proof.ProofValidatorFactory;
import io.mosip.certify.utils.CredentialUtils;
import io.mosip.certify.utils.DIDDocumentUtil;
import io.mosip.certify.utils.LedgerUtils;
import io.mosip.certify.utils.VCIssuanceUtil;
import io.mosip.certify.vcformatters.VCFormatter;
import io.mosip.pixelpass.PixelPass;
import io.mosip.pixelpass.shared.ConstantsKt;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.certify.utils.CredentialUtils.toJsonMap;
import static io.mosip.certify.utils.VCIssuanceUtil.getScopeCredentialMapping;

@Slf4j
@Service
@ConditionalOnProperty(value = "mosip.certify.plugin-mode", havingValue = "DataProvider")
public class CertifyIssuanceServiceImpl implements VCIssuanceService {

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
    private VCICacheService vcICacheService;

    @Autowired
    private AuditPlugin auditWrapper;

    @Autowired
    @Qualifier("certifyPixelPass")
    private PixelPass pixelPass;

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

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Autowired
    private VelocityEnvConfig velocityEnvConfig;

    @Override
    public CredentialResponse getCredential(CredentialRequest credentialRequest) {
        // 1. Credential Request validation
        List<VCResult<?>> vcResults = new ArrayList<>();
        if(!parsedAccessToken.isActive())
            throw new NotAuthenticatedException();
        // 2. Scope Validation
        String scopeClaim = (String) parsedAccessToken.getClaims().getOrDefault("scope", "");
        CredentialConfigurationSupported credentialConfigurationSupported = null;
        CredentialIssuerMetadataDTO credentialIssuerMetadataDTO = credentialConfigurationService.fetchCredentialIssuerMetadata();
        for(String scope : scopeClaim.split(Constants.SPACE)) {
            Optional<CredentialConfigurationSupported> result = getScopeCredentialMapping(
                    scope, credentialRequest.getCredentialConfigId(), credentialIssuerMetadataDTO);
            if(result.isPresent()) {
                credentialConfigurationSupported = result.get(); //considering only first credential scope
                break;
            }
        }

        if(credentialConfigurationSupported == null) {
            log.error("No credential mapping found for the provided scope {}", scopeClaim);
            throw new CertifyException(VCIErrorConstants.INVALID_SCOPE, "No credential mapping found for the provided scope.");
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
                    String validCNonce = VCIssuanceUtil.validateAndGetClientNonce(vcICacheService, proofValue, log, nonceEndpoint);

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

        auditWrapper.logAudit(Action.PROOF_VALIDATION, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);

        for (String holderId : holderIds) {
            vcResults.add(getVerifiableCredential(credentialConfigurationSupported, holderId));
        }

        auditWrapper.logAudit(Action.VC_ISSUANCE, ActionStatus.SUCCESS,
                AuditHelper.buildAuditDto(accessTokenHash, "accessTokenHash"), null);
        return VCIssuanceUtil.getCredentialResponse(credentialConfigurationSupported.getFormat(), vcResults);
    }

    @Override
    public Map<String, Object> getDIDDocument() {
        didDocument = didDocumentUtil.generateDIDDocument(didUrl);
        return didDocument;
    }

    private VCResult<?> getVerifiableCredential(CredentialConfigurationSupported credentialConfigurationSupported, String holderId) {
        parsedAccessToken.getClaims().put("accessTokenHash", parsedAccessToken.getAccessTokenHash());
        VCRequestDto vcRequestDto = new VCRequestDto();
        vcRequestDto.setFormat(credentialConfigurationSupported.getFormat());

        try {
            // Fetch data once, as it's common to all formats
            JSONObject jsonObject = dataProviderPlugin.fetchData(parsedAccessToken.getClaims());
            log.info("Data fetched successfully from Data Provider Plugin");

            String templateName;
            Map<String, Object> templateParams = new HashMap<>();
            String format = credentialConfigurationSupported.getFormat();

            // Handle format-specific setup
            switch (format) {
                case VCFormats.LDP_VC:
                    vcRequestDto.setContext(credentialConfigurationSupported.getContext());
                    vcRequestDto.setType(credentialConfigurationSupported.getTypes());
                    templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    jsonObject.put(Constants.TYPE, credentialConfigurationSupported.getTypes());

                    List<String> credentialStatusPurposeList = vcFormatter.getCredentialStatusPurpose(templateName);
                    if (credentialStatusPurposeList != null && !credentialStatusPurposeList.isEmpty()
                            && credentialConfigurationSupported.getContext() != null
                            && credentialConfigurationSupported.getContext().contains(VCDM2Constants.URL)) {
                        if(!isLedgerEnabled) {
                            log.warn("Ledger feature is currently disabled. Since revocation is enabled, please note that searching for VCs to revoke within Certify is not available.");
                        }
                        statusListCredentialService.addCredentialStatus(jsonObject, credentialStatusPurposeList.getFirst());
                    }
                    break;

                case VCFormats.DC_SD_JWT:
                    vcRequestDto.setVct(credentialConfigurationSupported.getVct());
                    templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put(Constants.VCTYPE, vcRequestDto.getVct());
                    templateParams.put(Constants.CONFIRMATION, Map.of("kid", holderId));
                    templateParams.put(Constants.ISSUER, certifyIssuer);
                    jsonObject.put(Constants.TYPE, vcRequestDto.getVct());
                    break;

                case VCFormats.MSO_MDOC:
                    vcRequestDto.setDoctype(credentialConfigurationSupported.getDocType());
                    templateName = CredentialUtils.getTemplateName(vcRequestDto);
                    templateParams.put("_doctype", vcRequestDto.getDoctype());
                    jsonObject.put(Constants.TYPE, vcRequestDto.getDoctype());
                    break;

                default:
                    throw new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT, "Invalid or unsupported VC format requested.");

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

            Credential cred = credentialFactory.getCredential(format).orElseThrow(() -> new CertifyException(VCIErrorConstants.UNSUPPORTED_CREDENTIAL_FORMAT));
            Map<String, Object> updatedTemplateParams = toJsonMap(templateParams);
            Map<String, Object> rootContext = new HashMap<>(templateParams);
            updatedTemplateParams.put("rootContext", rootContext);
            updatedTemplateParams.put("envConfigs", velocityEnvConfig.getEnvConfigs());

            log.info("Template parameters updated with root context");

            JSONArray qrDataJson = cred.createQRData(updatedTemplateParams, templateName);
            log.info("QR data JSON generated successfully");

            if (qrDataJson != null) {
                try {
                    List<String> claim169Values = signQrEntries(cred, qrDataJson, templateName);
                    updatedTemplateParams.put("claim_169_values", claim169Values);
                    log.info("Claim 169 values signed successfully for template");
                } catch (JsonProcessingException e) {
                    log.error(e.getMessage(), e);
                    throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Invalid JSON data encountered during credential generation. Please check the data provider response and template configurations.");
                } catch (CertifyException e) {
                    log.error(e.getMessage(), e);
                    throw e;
                } catch (Exception e) {
                    log.error("Error during signing qr data: {}", e.getMessage());
                    throw new CertifyException(ErrorConstants.ERROR_SIGNING_QR_DATA, e.getMessage());
                }
            } else {
                log.warn("QR code not configured for template: {}. To enable qr code support, update the respective credential configuration.", templateName);
            }

            String unsignedCredential = cred.createCredential(updatedTemplateParams, templateName);
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
            throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Invalid JSON data encountered during credential generation. Please check the data provider response and template configurations.");
        } catch (CertifyException e) {
            log.error("CertifyException during credential generation: {}", e.getMessage());
            throw e;
        }
    }

    private List<String> signQrEntries(Credential cred, JSONArray qrDataJson, String templateName) throws JsonProcessingException {
        List<String> signedQrCodes = new ArrayList<>();
        if (qrDataJson == null || qrDataJson.isEmpty()) {
            log.info("No QR data entries found to sign");
            return signedQrCodes;
        }
        Map<String, Integer> claim169KeyMapper = ConstantsKt.getCLAIM_169_KEY_MAPPER();
        log.info("Claim 169 key mapper initialized successfully");
        Map<String, Map<Object, Integer>> claim169ValueMapper = ConstantsKt.getCLAIM_169_VALUE_MAPPER();
        log.info("Claim 169 value mapping completed");
        for (int i = 0; i < qrDataJson.length(); i++) {
            Object qrObj = qrDataJson.get(i);
            log.info("Processing QR entry index {}", i);
            String claim169MappedData;
            if (qrObj instanceof JSONObject) {
                claim169MappedData = pixelPass
                        .getMappedData((JSONObject) qrObj, claim169KeyMapper,
                                claim169ValueMapper, true).toString();
            } else {
                log.error("Invalid QR Data json found. The qrSettings needs to be fixed.");
                throw new CertifyException(ErrorConstants.JSON_PROCESSING_ERROR, "Unsupported QR entry type: " + qrObj.getClass().getName());
            }

            log.info("Claim 169 mapped data for QR entry index {}", i);

            // Default QR Signer Configuration
            String qrSignatureAlgo = vcFormatter.getQRSignatureAlgo(templateName);
            String qrSignAppId = vcFormatter.getAppID(templateName);
            String qrSignRefId = vcFormatter.getRefID(templateName);

            // Override with QR specific signers if available
            if(qrSignatureAlgo == null || qrSignatureAlgo.isEmpty()) {
                log.warn("No QR specific signature algorithm configured for template: {}. Falling back to default signature algorithm.", templateName);
                qrSignatureAlgo = vcFormatter.getProofAlgorithm(templateName);
            } else {
                log.info("Using QR specific signature algorithm: {} for template: {}", qrSignatureAlgo, templateName);
                List<List<String>> qrSignerKeysList = keyAliasMapper.get(qrSignatureAlgo);
                if (qrSignerKeysList == null || qrSignerKeysList.isEmpty()) {
                    throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND,
                            "No key configuration found for QR signature algorithm: " + qrSignatureAlgo);
                }
                List<String> qrSignerKeys = qrSignerKeysList.getFirst();
                qrSignAppId = qrSignerKeys.getFirst();
                qrSignRefId = qrSignerKeys.getLast();
            }
            try {
                // call addCWTProof to sign this QR payload; adapt params if Signature/API differs
                String qrSignedResult = cred.signQRData(
                        claim169MappedData,
                        qrSignatureAlgo,
                        qrSignAppId,
                        qrSignRefId,
                        domainUrl
                );
                log.info("Signed QR data for entry index {}", i);
                if (qrSignedResult != null && !qrSignedResult.isEmpty()) {
                    try {
                        log.info("Generating QR code for signed QR entry index {}.", i);
                        signedQrCodes.add(pixelPass.generateQRData(qrSignedResult, ""));
                        log.info("QR code generation successful for entry {}", i);
                    } catch (Exception e) {
                        log.error("Failed to generate QR code for signed QR entry index {}: {}", i, e.getMessage());
                        throw new CertifyException(ErrorConstants.QR_CBOR_ENCODING_ERROR, e.getMessage());
                    }
                    continue;
                }
                throw new CertifyException(ErrorConstants.INVALID_QR_SIGNED_RESULT, "QR signed result failed at index: " + i);
            } catch (Exception e) {
                log.error("Failed to sign QR entry index {}: {}", i, e.getMessage());
                // signing failure is non-recoverable; propagate as domain exception
                throw new CertifyException(ErrorConstants.ERROR_SIGNING_QR_ENTRY, e.getMessage());
            }
        }
        log.info("Signed QR codes generated successfully for template");
        return signedQrCodes;
    }
}
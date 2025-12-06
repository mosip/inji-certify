/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.util.CommonUtil;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.partnercertservice.dto.CACertificateRequestDto;
import io.mosip.kernel.partnercertservice.dto.CACertificateResponseDto;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.util.Optional;

/**
 * Controller GET Certify service certificates
 */
@Slf4j
@RestController
@RequestMapping("/system-info")
public class SystemInfoController {

    @Autowired
    private KeymanagerService keymanagerService;

    @Autowired
    private PartnerCertificateManagerService partnerCertificateManagerService;
    
    @Autowired
    AuditPlugin auditWrapper;
    
    @Value("${mosip.certify.audit.claim-name:preferred_username}")
    private String claimName;

    @GetMapping(value = "/certificate")
    public ResponseWrapper<KeyPairGenerateResponseDto> getCertificate(
            @Valid @NotBlank(message = ErrorConstants.INVALID_REQUEST) @RequestParam("applicationId") String applicationId,
            @RequestParam("referenceId") Optional<String> referenceId) {
        ResponseWrapper<KeyPairGenerateResponseDto> responseWrapper = new ResponseWrapper<>();
        try {
        	responseWrapper.setResponse(keymanagerService.getCertificate(applicationId, referenceId));
        } catch (CertifyException ex) {
        	throw ex;
        }
        responseWrapper.setResponseTime(CommonUtil.getUTCDateTime());
        return responseWrapper;
    }

    @PostMapping(value = "/uploadCertificate")
    public ResponseWrapper<UploadCertificateResponseDto> uploadSignedCertificate(
            @Valid @RequestBody RequestWrapper<UploadCertificateRequestDto> requestWrapper) {
        ResponseWrapper<UploadCertificateResponseDto> responseWrapper = new ResponseWrapper<>();
        UploadCertificateRequestDto uploadCertificateRequestDto = requestWrapper.getRequest();
        try {
        	responseWrapper.setResponse(keymanagerService.uploadCertificate(uploadCertificateRequestDto));
        } catch (CertifyException ex) {
            throw ex;
        }
        responseWrapper.setResponseTime(CommonUtil.getUTCDateTime());
        return responseWrapper;
    }

    @PostMapping("/generate-csr")
    public ResponseWrapper<KeyPairGenerateResponseDto> generateCSR(
            @Valid @RequestBody RequestWrapper<CSRGenerateRequestDto> requestWrapper) {

        ResponseWrapper<KeyPairGenerateResponseDto> responseWrapper = new ResponseWrapper<>();
        CSRGenerateRequestDto csrGenerateRequestDto = requestWrapper.getRequest();
        log.info("CSR Generation request received for applicationId: {}, referenceId: {}", csrGenerateRequestDto.getApplicationId(), csrGenerateRequestDto.getReferenceId());
        try {
            responseWrapper.setResponse(keymanagerService.generateCSR(csrGenerateRequestDto));
        } catch (CertifyException ex) {
            log.error("Error during CSR generation: {}", ex.getMessage(), ex);
            throw ex;
        }

        responseWrapper.setResponseTime(CommonUtil.getUTCDateTime());
        return responseWrapper;
    }

    @PostMapping("/upload-ca-certificate")
    public ResponseWrapper<CACertificateResponseDto> uploadCACertificate(
            @Valid @RequestBody RequestWrapper<CACertificateRequestDto> requestWrapper) {

        ResponseWrapper<CACertificateResponseDto> responseWrapper = new ResponseWrapper<>();
        CACertificateRequestDto caCertificateRequestDto = requestWrapper.getRequest();
        log.info("Upload CA Certificate request received for partnerDomain: {}", caCertificateRequestDto.getPartnerDomain());
        try {
            responseWrapper.setResponse(partnerCertificateManagerService.uploadCACertificate(caCertificateRequestDto));
        } catch (CertifyException ex) {
            log.error("Error during CA certificate upload: {}", ex.getMessage(), ex);
            throw ex;
        }

        responseWrapper.setResponseTime(CommonUtil.getUTCDateTime());
        return responseWrapper;
    }
}

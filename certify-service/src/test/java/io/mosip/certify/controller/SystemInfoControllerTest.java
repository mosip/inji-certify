/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.controller;

import io.mosip.certify.api.spi.AuditPlugin;
import io.mosip.certify.core.dto.ResponseWrapper;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.keymanagerservice.dto.CSRGenerateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.KeyPairGenerateResponseDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateRequestDto;
import io.mosip.kernel.keymanagerservice.dto.UploadCertificateResponseDto;
import io.mosip.kernel.keymanagerservice.service.KeymanagerService;
import io.mosip.kernel.partnercertservice.dto.CACertificateRequestDto;
import io.mosip.kernel.partnercertservice.dto.CACertificateResponseDto;
import io.mosip.kernel.partnercertservice.service.spi.PartnerCertificateManagerService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Optional;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SystemInfoControllerTest {

    @Mock
    private KeymanagerService keymanagerService;

    @Mock
    private PartnerCertificateManagerService partnerCertificateManagerService;

    @Mock
    private AuditPlugin auditWrapper;

    @InjectMocks
    private SystemInfoController systemInfoController;

    @Test
    public void getCertificate_success() {
        KeyPairGenerateResponseDto dto = new KeyPairGenerateResponseDto();
        when(keymanagerService.getCertificate(eq("APP_ID"), any())).thenReturn(dto);

        ResponseWrapper<KeyPairGenerateResponseDto> response =
                systemInfoController.getCertificate("APP_ID", Optional.of("REF_ID"));

        assertSame(dto, response.getResponse());
        assertNotNull(response.getResponseTime());
    }

    @Test
    public void getCertificate_propagatesCertifyException() {
        when(keymanagerService.getCertificate(any(), any())).thenThrow(new CertifyException("err"));
        assertThrows(CertifyException.class, () ->
                systemInfoController.getCertificate("APP_ID", Optional.empty()));
    }

    @Test
    public void uploadSignedCertificate_success() {
        UploadCertificateResponseDto dto = new UploadCertificateResponseDto();
        when(keymanagerService.uploadCertificate(any())).thenReturn(dto);
        RequestWrapper<UploadCertificateRequestDto> request = new RequestWrapper<>();
        request.setRequest(new UploadCertificateRequestDto());

        ResponseWrapper<UploadCertificateResponseDto> response =
                systemInfoController.uploadSignedCertificate(request);

        assertSame(dto, response.getResponse());
        assertNotNull(response.getResponseTime());
    }

    @Test
    public void uploadSignedCertificate_propagatesCertifyException() {
        when(keymanagerService.uploadCertificate(any())).thenThrow(new CertifyException("err"));
        RequestWrapper<UploadCertificateRequestDto> request = new RequestWrapper<>();
        request.setRequest(new UploadCertificateRequestDto());
        assertThrows(CertifyException.class, () -> systemInfoController.uploadSignedCertificate(request));
    }

    @Test
    public void generateCSR_success() {
        KeyPairGenerateResponseDto dto = new KeyPairGenerateResponseDto();
        when(keymanagerService.generateCSR(any())).thenReturn(dto);
        RequestWrapper<CSRGenerateRequestDto> request = new RequestWrapper<>();
        CSRGenerateRequestDto csr = new CSRGenerateRequestDto();
        csr.setApplicationId("APP_ID");
        csr.setReferenceId("REF_ID");
        request.setRequest(csr);

        ResponseWrapper<KeyPairGenerateResponseDto> response = systemInfoController.generateCSR(request);

        assertSame(dto, response.getResponse());
        assertNotNull(response.getResponseTime());
    }

    @Test
    public void generateCSR_propagatesCertifyException() {
        when(keymanagerService.generateCSR(any())).thenThrow(new CertifyException("err"));
        RequestWrapper<CSRGenerateRequestDto> request = new RequestWrapper<>();
        CSRGenerateRequestDto csr = new CSRGenerateRequestDto();
        csr.setApplicationId("APP_ID");
        csr.setReferenceId("REF_ID");
        request.setRequest(csr);
        assertThrows(CertifyException.class, () -> systemInfoController.generateCSR(request));
    }

    @Test
    public void uploadCACertificate_success() {
        CACertificateResponseDto dto = new CACertificateResponseDto();
        when(partnerCertificateManagerService.uploadCACertificate(any())).thenReturn(dto);
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto ca = new CACertificateRequestDto();
        ca.setPartnerDomain("AUTH");
        request.setRequest(ca);

        ResponseWrapper<CACertificateResponseDto> response = systemInfoController.uploadCACertificate(request);

        assertSame(dto, response.getResponse());
        assertNotNull(response.getResponseTime());
    }

    @Test
    public void uploadCACertificate_propagatesCertifyException() {
        when(partnerCertificateManagerService.uploadCACertificate(any())).thenThrow(new CertifyException("err"));
        RequestWrapper<CACertificateRequestDto> request = new RequestWrapper<>();
        CACertificateRequestDto ca = new CACertificateRequestDto();
        ca.setPartnerDomain("AUTH");
        request.setRequest(ca);
        assertThrows(CertifyException.class, () -> systemInfoController.uploadCACertificate(request));
    }
}

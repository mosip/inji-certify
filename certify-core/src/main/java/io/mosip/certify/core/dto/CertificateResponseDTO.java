package io.mosip.certify.core.dto;

import lombok.Data;

import java.io.Serializable;

@Data
public class CertificateResponseDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private String keyId;
    private String certificateData;
}

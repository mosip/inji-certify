package io.mosip.certify.core.dto;

import lombok.Builder;
import lombok.Data;
import java.io.Serializable;
import java.util.Map;

@Data
@Builder // Add this
public class Transaction implements Serializable {
    private static final long serialVersionUID = 1L; // Add this

    private String credentialConfigurationId;
    private Map<String, Object> claims;
    private String cNonce;
    private long cNonceExpiresAt;
    private long createdAt;
}
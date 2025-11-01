package io.mosip.certify.core.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
public class Transaction {
    private String credentialConfigurationId;
    private Map<String, Object> claims;
    private String cNonce;
    private long cNonceExpiresAt;
    private long createdAt;
}

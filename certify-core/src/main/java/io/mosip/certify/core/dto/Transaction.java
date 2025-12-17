package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.io.Serializable;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Transaction implements Serializable {
    private static final long serialVersionUID = 1L;

    private String credentialConfigurationId;
    private Map<String, Object> claims;
    private String cNonce;
    private long cNonceExpiresAt;
    private long createdAt;
}
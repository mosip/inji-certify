package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PreAuthCodeData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String credentialConfigurationId;
    private Map<String, Object> claims;
    private String txnCode;
    private long createdAt;
    private long expiresAt;
}
package io.mosip.certify.core.dto;

import java.util.Map;
import lombok.Data;

@Data
public class CredentialLedgerSearchRequest {
    private String credentialId;
    private String issuerId;
    private String credentialType;
    private Map<String, String> indexedAttributes;
}
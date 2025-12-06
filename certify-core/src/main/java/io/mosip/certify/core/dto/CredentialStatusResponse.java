package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;
import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CredentialStatusResponse {
    private String credentialId;
    private String issuerId;
    private String statusListCredentialUrl;
    private Long statusListIndex;
    private String statusPurpose;

    /**
     * @deprecated Use of version v2 i.e. {@link #issuanceDate} is recommended instead.
     * This field is deprecated and will be removed in future versions.
     */
    @Deprecated
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime issueDate;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime issuanceDate;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime expirationDate;
    
    private String credentialType;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime statusTimestamp;
}
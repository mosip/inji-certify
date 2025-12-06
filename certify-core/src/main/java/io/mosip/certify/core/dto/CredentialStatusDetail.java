package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CredentialStatusDetail implements Serializable {
    @JsonProperty("status_purpose")
    private String statusPurpose;
    @JsonProperty("status_list_credential_id")
    private String statusListCredentialId;
    @JsonProperty("status_list_index")
    private Long statusListIndex;
    @JsonProperty("cr_dtimes")
    private Long createdTimes;
}

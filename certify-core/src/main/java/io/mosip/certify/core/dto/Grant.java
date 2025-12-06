package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Grant {

    @JsonProperty("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    private PreAuthorizedCodeGrant preAuthorizedCode;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class PreAuthorizedCodeGrant {

        @JsonProperty("pre-authorized_code")
        private String preAuthorizedCode;

        @JsonProperty("tx_code")
        private TxCode txCode;
    }
}
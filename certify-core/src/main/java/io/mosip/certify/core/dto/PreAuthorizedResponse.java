package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PreAuthorizedResponse {
    private String credentialOfferUri;
}
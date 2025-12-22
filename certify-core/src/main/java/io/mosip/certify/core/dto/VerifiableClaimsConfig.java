/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

/**
 * Configuration structure for verifiable claims
 * Matches the format used in inji-verify's config.json
 */
@Data
public class VerifiableClaimsConfig {
    
    @JsonProperty("verifiableClaims")
    private List<VerifiableClaim> verifiableClaims;
    
    @Data
    public static class VerifiableClaim {
        private String logo;
        private String name;
        private String type;
        private Boolean essential;
        private ClaimDefinition definition;
    }
    
    @Data
    public static class ClaimDefinition {
        private String purpose;
        private Format format;
        
        @JsonProperty("input_descriptors")
        private List<InputDescriptor> inputDescriptors;
    }
    
    @Data
    public static class Format {
        @JsonProperty("ldp_vc")
        private LdpVc ldpVc;
    }
    
    @Data
    public static class LdpVc {
        @JsonProperty("proof_type")
        private List<String> proofType;
    }
    
    @Data
    public static class InputDescriptor {
        private String id;
        private Format format;
        private Constraints constraints;
    }
    
    @Data
    public static class Constraints {
        private List<FieldConstraint> fields;
    }
    
    @Data
    public static class FieldConstraint {
        private List<String> path;
        private Filter filter;
    }
    
    @Data
    public static class Filter {
        private String type;
        private String pattern;
    }
}

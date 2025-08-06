package io.mosip.certify.entity.attributes;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CredentialSubjectParameters implements Serializable {
    private List<Display> display;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Display implements Serializable {
        private String name;
        private String locale;
    }
}


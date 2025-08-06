package io.mosip.certify.core.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ClaimsDisplayFieldsConfigDTO {
    private List<Display> display;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Display {
        private String name;
        private String locale;
    }
}


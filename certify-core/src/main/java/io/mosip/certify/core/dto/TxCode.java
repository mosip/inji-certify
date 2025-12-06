package io.mosip.certify.core.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TxCode {

    @JsonProperty("length")
    private Integer length;

    @JsonProperty("input_mode")
    @Pattern(
            regexp = "numeric|text",
            message = "input_mode must be either 'numeric' or 'text'"
    )
    private String inputMode;

    @JsonProperty("description")
    private String description;
}
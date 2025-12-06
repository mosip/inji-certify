package io.mosip.certify.core.dto;

import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;

@Data
public class RenderingTemplateDTO implements Serializable {
    private static final long serialVersionUID = 1L;

    private String id;
    private String template;
    private LocalDateTime createdTimes;
    private LocalDateTime updatedTimes;
}

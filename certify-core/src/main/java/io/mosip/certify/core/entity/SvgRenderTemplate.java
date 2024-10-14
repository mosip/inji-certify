package io.mosip.certify.core.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
public class SvgRenderTemplate {
    @Id
    @NotBlank
    private String id;

    @NotBlank(message = "Template should not be empty")
    @Column(name = "svg_template")
    private String svgTemplate;

    @Column(name = "last_modified")
    private LocalDateTime lastModified;
}

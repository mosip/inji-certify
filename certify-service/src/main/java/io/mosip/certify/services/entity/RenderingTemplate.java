/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services.entity;

import io.mosip.certify.core.constants.ErrorConstants;
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
@Table(name = "rendering_template")
public class RenderingTemplate {
    @Id
    private String id;

    @NotBlank(message = ErrorConstants.EMPTY_TEMPLATE_CONTENT)
    @Column(name = "template")
    private String template;

    @Column(name = "cr_dtimes")
    private LocalDateTime createdtimes;

    @Column(name = "upd_dtimes")
    private LocalDateTime updatedtimes;
}

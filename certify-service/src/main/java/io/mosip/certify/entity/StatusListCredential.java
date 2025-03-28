package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "status_list_credential", uniqueConstraints = @UniqueConstraint(columnNames = {"issuer_id", "status_purpose"}))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class StatusListCredential {
    @Id
    private String id;

    @Column(name = "issuer_id", nullable = false)
    private String issuerId;

    @Column(name = "type", nullable = false, columnDefinition = "VARCHAR(100) DEFAULT 'BitstringStatusListCredential'")
    private String type = "BitstringStatusListCredential";

    @Lob
    @Column(name = "encoded_list", nullable = false)
    private String encodedList;

    @Column(name = "list_size", nullable = false)
    private Integer listSize;

    @Column(name = "status_purpose", nullable = false)
    private String statusPurpose;

    @Column(name = "status_size", columnDefinition = "integer DEFAULT 1")
    private Integer statusSize = 1;

    @Column(name = "status_messages", columnDefinition = "jsonb")
    @JdbcTypeCode(SqlTypes.JSON)
    private String statusMessages;

    @Column(name = "valid_from", nullable = false)
    private LocalDateTime validFrom;

    @Column(name = "valid_until")
    private LocalDateTime validUntil;

    @Column(name = "ttl")
    private Long ttl;
}
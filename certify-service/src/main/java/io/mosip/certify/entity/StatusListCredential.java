package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.*;
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
    private String statusMessages;
    
    @Column(name = "valid_from", nullable = false)
    private LocalDateTime validFrom;
    
    @Column(name = "valid_until")
    private LocalDateTime validUntil;
    
    @Column(name = "ttl")
    private Long ttl;
    
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt = LocalDateTime.now();
    
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt = LocalDateTime.now();
    
    @Column(name = "cr_by", nullable = false)
    private String createdBy;
    
    @Column(name = "cr_dtimes", nullable = false)
    private LocalDateTime createdTimes;
    
    @Column(name = "upd_by")
    private String updatedBy;
    
    @Column(name = "upd_dtimes")
    private LocalDateTime updatedTimes;
    
    @Column(name = "is_deleted", columnDefinition = "BOOLEAN DEFAULT FALSE")
    private Boolean isDeleted;
    
    @Column(name = "del_dtimes")
    private LocalDateTime deletedTimes;
}
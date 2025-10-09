package io.mosip.certify.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "iar_session")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class IarSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "auth_session", length = 128, nullable = false, unique = true)
    private String authSession;

    @Column(name = "transaction_id", length = 64, nullable = false)
    private String transactionId;

    @Column(name = "request_id", length = 64)
    private String requestId;

    @Column(name = "verify_nonce", length = 64)
    private String verifyNonce;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "client_id", length = 128)
    private String clientId;

    @Column(name = "authorization_code", length = 128)
    private String authorizationCode;

    @Column(name = "response_uri", length = 512)
    private String responseUri;

    @Column(name = "code_challenge", length = 128)
    private String codeChallenge;

    @Column(name = "code_challenge_method", length = 10)
    private String codeChallengeMethod;

    @Column(name = "code_issued_at")
    private LocalDateTime codeIssuedAt;

    @Column(name = "is_code_used", nullable = false)
    private Boolean isCodeUsed = false;

    @Column(name = "code_used_at")
    private LocalDateTime codeUsedAt;

    @Column(name = "cr_dtimes", nullable = false, updatable = false)
    private LocalDateTime createdDtimes;

    @PrePersist
    protected void onCreate() {
        createdDtimes = LocalDateTime.now();
    }
}



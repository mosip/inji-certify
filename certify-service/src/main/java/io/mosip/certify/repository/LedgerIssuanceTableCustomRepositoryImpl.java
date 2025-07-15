package io.mosip.certify.repository;

import io.mosip.certify.core.dto.CredentialLedgerSearchRequest;
import io.mosip.certify.entity.Ledger;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.stereotype.Repository;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class LedgerIssuanceTableCustomRepositoryImpl implements LedgerIssuanceTableCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    private final ObjectMapper objectMapper;

    public LedgerIssuanceTableCustomRepositoryImpl(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public List<Ledger> findBySearchRequest(CredentialLedgerSearchRequest request) {
        try {
            StringBuilder sql = new StringBuilder("SELECT * FROM ledger WHERE issuer_id = :issuerId AND credential_type = :credentialType ");
            Map<String, Object> params = new HashMap<>();
            params.put("issuerId", request.getIssuerId());
            params.put("credentialType", request.getCredentialType());

            if (request.getCredentialId() != null) {
                sql.append(" AND credential_id = :credentialId ");
                params.put("credentialId", request.getCredentialId());
            }

            if (request.getIndexedAttributesEquals() != null && !request.getIndexedAttributesEquals().isEmpty()) {
                int i = 0;
                for (Map.Entry<String, String> entry : request.getIndexedAttributesEquals().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();
                    if (key == null || key.isBlank() || value == null || value.isBlank()) continue;

                    String paramName = "indexedAttr" + i;
                    sql.append(" AND indexed_attributes @> cast(:" + paramName + " AS jsonb) ");
                    params.put(paramName, objectMapper.writeValueAsString(Map.of(key, value)));
                    i++;
                }
            }

            var query = entityManager.createNativeQuery(sql.toString(), Ledger.class);

            for (Map.Entry<String, Object> entry : params.entrySet()) {
                query.setParameter(entry.getKey(), entry.getValue());
            }

            return query.getResultList();
        } catch (Exception e) {
            throw new RuntimeException("Failed to search LedgerIssuanceTable", e);
        }
    }
}

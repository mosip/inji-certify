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

    @Override
    public List<Ledger> findBySearchRequest(CredentialLedgerSearchRequest request) {
        try {
            StringBuilder sql = new StringBuilder("SELECT * FROM ledger WHERE 1=1 ");
            Map<String, Object> params = new HashMap<>();
            System.out.println("params: " + params);

            if (request.getIssuerId() != null) {
                sql.append(" AND issuer_id = :issuerId ");
                params.put("issuerId", request.getIssuerId());
            }

            if (request.getCredentialType() != null) {
                sql.append(" AND credential_type = :credentialType ");
                params.put("credentialType", request.getCredentialType());
            }

            if (request.getCredentialId() != null) {
                sql.append(" AND credential_id = :credentialId ");
                params.put("credentialId", request.getCredentialId());
            }

            if (request.getIndexedAttributes() != null && !request.getIndexedAttributes().isEmpty()) {
                int i = 0;
                for (Map.Entry<String, String> entry : request.getIndexedAttributes().entrySet()) {
                    String key = entry.getKey();
                    String value = entry.getValue();
                    if (key == null || key.isBlank() || value == null || value.isBlank()) {
                        continue;
                    }
                    String paramName = "indexedAttr" + i;
                    sql.append(" AND indexed_attributes @> cast(:" + paramName + " AS jsonb) ");
                    params.put(paramName, new ObjectMapper().writeValueAsString(Map.of(key, value)));
                    i++;
                }
            }

            var query = entityManager.createNativeQuery(sql.toString(), Ledger.class);
            System.out.println(query.toString() + "query.toString()");

            for (Map.Entry<String, Object> entry : params.entrySet()) {
                query.setParameter(entry.getKey(), entry.getValue());
            }

            return query.getResultList();
        } catch (Exception e) {
            throw new RuntimeException("Failed to search LedgerIssuanceTable", e);
        }
    }
}

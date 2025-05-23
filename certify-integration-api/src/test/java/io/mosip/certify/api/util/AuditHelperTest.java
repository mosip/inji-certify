package io.mosip.certify.api.util;

import io.mosip.certify.api.dto.AuditDTO;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AuditHelperTest {

    @Nested
    @DisplayName("Tests for buildAuditDto(String clientId)")
    class BuildAuditDtoWithClientId {

        @Test
        @DisplayName("Test with a sample clientId")
        void testBuildAuditDto_withSampleClientId() {
            String clientId = "testClient123";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(clientId);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(clientId, auditDTO.getClientId(), "ClientId should match the input");
            assertEquals(clientId, auditDTO.getTransactionId(), "TransactionId should match the clientId");
            assertEquals("ClientId", auditDTO.getIdType(), "IdType should be 'ClientId'");
        }

        @Test
        @DisplayName("Test with a null clientId")
        void testBuildAuditDto_withNullClientId() {
            AuditDTO auditDTO = AuditHelper.buildAuditDto(null);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
            assertNull(auditDTO.getTransactionId(), "TransactionId should be null");
            assertEquals("ClientId", auditDTO.getIdType(), "IdType should be 'ClientId'");
        }

        @Test
        @DisplayName("Test with an empty clientId")
        void testBuildAuditDto_withEmptyClientId() {
            String clientId = "";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(clientId);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(clientId, auditDTO.getClientId(), "ClientId should be an empty string");
            assertEquals(clientId, auditDTO.getTransactionId(), "TransactionId should be an empty string");
            assertEquals("ClientId", auditDTO.getIdType(), "IdType should be 'ClientId'");
        }
    }

    @Nested
    @DisplayName("Tests for buildAuditDto(String transactionId, String idType)")
    class BuildAuditDtoWithTransactionIdAndIdType {

        @Test
        @DisplayName("Test with sample transactionId and idType")
        void testBuildAuditDto_withSampleTransactionIdAndIdType() {
            String transactionId = "tx123";
            String idType = "VID";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(transactionId, idType);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(transactionId, auditDTO.getTransactionId(), "TransactionId should match the input");
            assertEquals(idType, auditDTO.getIdType(), "IdType should match the input");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with null transactionId and sample idType")
        void testBuildAuditDto_withNullTransactionId() {
            String idType = "VID";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(null, idType);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertNull(auditDTO.getTransactionId(), "TransactionId should be null");
            assertEquals(idType, auditDTO.getIdType(), "IdType should match the input");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with sample transactionId and null idType")
        void testBuildAuditDto_withNullIdType() {
            String transactionId = "tx123";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(transactionId, null);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(transactionId, auditDTO.getTransactionId(), "TransactionId should match the input");
            assertNull(auditDTO.getIdType(), "IdType should be null");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with null transactionId and null idType")
        void testBuildAuditDto_withNullTransactionIdAndNullIdType() {
            AuditDTO auditDTO = AuditHelper.buildAuditDto(null, null);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertNull(auditDTO.getTransactionId(), "TransactionId should be null");
            assertNull(auditDTO.getIdType(), "IdType should be null");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with empty transactionId and sample idType")
        void testBuildAuditDto_withEmptyTransactionId() {
            String transactionId = "";
            String idType = "VID";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(transactionId, idType);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(transactionId, auditDTO.getTransactionId(), "TransactionId should be an empty string");
            assertEquals(idType, auditDTO.getIdType(), "IdType should match the input");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with sample transactionId and empty idType")
        void testBuildAuditDto_withEmptyIdType() {
            String transactionId = "tx123";
            String idType = "";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(transactionId, idType);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(transactionId, auditDTO.getTransactionId(), "TransactionId should match the input");
            assertEquals(idType, auditDTO.getIdType(), "IdType should be an empty string");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }

        @Test
        @DisplayName("Test with empty transactionId and empty idType")
        void testBuildAuditDto_withEmptyTransactionIdAndEmptyIdType() {
            String transactionId = "";
            String idType = "";
            AuditDTO auditDTO = AuditHelper.buildAuditDto(transactionId, idType);

            assertNotNull(auditDTO, "AuditDTO should not be null");
            assertEquals(transactionId, auditDTO.getTransactionId(), "TransactionId should be an empty string");
            assertEquals(idType, auditDTO.getIdType(), "IdType should be an empty string");
            assertNull(auditDTO.getClientId(), "ClientId should be null");
        }
    }
}

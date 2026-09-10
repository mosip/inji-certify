/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.entity.StatusListCredential;
import io.mosip.certify.repository.StatusListAvailableIndicesRepository;
import io.mosip.certify.repository.StatusListCredentialRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class DatabaseStatusListIndexProviderTest {

    @Mock
    private StatusListAvailableIndicesRepository statusListAvailableIndicesRepository;

    @Mock
    private StatusListCredentialRepository statusListCredentialRepository;

    @Mock
    private EntityManager entityManager;

    @Mock
    private Query query;

    @InjectMocks
    private DatabaseStatusListIndexProvider provider;

    @Before
    public void setup() {
        ReflectionTestUtils.setField(provider, "usableCapacityPercentage", 50);
        when(entityManager.createNativeQuery(anyString())).thenReturn(query);
        when(query.setParameter(anyString(), any())).thenReturn(query);
    }

    private StatusListCredential statusList(long capacityKb) {
        StatusListCredential list = new StatusListCredential();
        list.setId("list-1");
        list.setCapacityInKB(capacityKb);
        return list;
    }

    @Test
    public void getProviderName() {
        assertEquals("DatabaseRandomAvailableIndexProvider", provider.getProviderName());
    }

    @Test
    public void acquireIndex_listNotFound_returnsEmpty() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.empty());
        assertTrue(provider.acquireIndex("list-1", Collections.emptyMap()).isEmpty());
    }

    @Test
    public void acquireIndex_success_bigIntegerResult() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(statusList(1L)));
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(0L);
        when(query.getSingleResult()).thenReturn(BigInteger.valueOf(42));

        Optional<Long> result = provider.acquireIndex("list-1", Collections.emptyMap());
        assertTrue(result.isPresent());
        assertEquals(Long.valueOf(42), result.get());
    }

    @Test
    public void acquireIndex_success_longResult() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(statusList(1L)));
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(0L);
        when(query.getSingleResult()).thenReturn(7L);

        assertEquals(Long.valueOf(7), provider.acquireIndex("list-1", Collections.emptyMap()).get());
    }

    @Test
    public void acquireIndex_success_integerResult() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(statusList(1L)));
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(0L);
        when(query.getSingleResult()).thenReturn(9);

        assertEquals(Long.valueOf(9), provider.acquireIndex("list-1", Collections.emptyMap()).get());
    }

    @Test
    public void acquireIndex_capacityReached_marksFullAndReturnsEmpty() {
        StatusListCredential list = statusList(1L);
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(list));
        // physical capacity = 1*1024*8 = 8192; threshold 50% = 4096
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(5000L);

        Optional<Long> result = provider.acquireIndex("list-1", Collections.emptyMap());

        assertTrue(result.isEmpty());
        ArgumentCaptor<StatusListCredential> captor = ArgumentCaptor.forClass(StatusListCredential.class);
        verify(statusListCredentialRepository).save(captor.capture());
        assertEquals(StatusListCredential.CredentialStatus.FULL, captor.getValue().getCredentialStatus());
    }

    @Test
    public void acquireIndex_nullClaimResult_returnsEmpty() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(statusList(1L)));
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(0L);
        when(query.getSingleResult()).thenReturn(null);

        assertTrue(provider.acquireIndex("list-1", Collections.emptyMap()).isEmpty());
    }

    @Test
    public void acquireIndex_claimThrows_returnsEmpty() {
        when(statusListCredentialRepository.findById("list-1")).thenReturn(Optional.of(statusList(1L)));
        when(statusListAvailableIndicesRepository.countByStatusListCredentialIdAndIsAssignedTrue("list-1"))
                .thenReturn(0L);
        when(query.getSingleResult()).thenThrow(new RuntimeException("no rows"));

        assertTrue(provider.acquireIndex("list-1", Collections.emptyMap()).isEmpty());
    }

    @Test
    public void acquireIndex_repositoryThrows_returnsEmpty() {
        when(statusListCredentialRepository.findById("list-1")).thenThrow(new RuntimeException("db down"));
        assertTrue(provider.acquireIndex("list-1", Collections.emptyMap()).isEmpty());
    }
}

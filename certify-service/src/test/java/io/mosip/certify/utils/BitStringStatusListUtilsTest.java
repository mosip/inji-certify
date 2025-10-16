package io.mosip.certify.utils;

import io.mosip.certify.core.exception.CertifyException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class BitStringStatusListUtilsTest {

    @Test
    public void updateEncodedList_WithValidInputs_ReturnsEncodedString() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(0L, true);
        statusMap.put(1L, false);
        statusMap.put(10L, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 16L);

        assertNotNull(result);
        assertTrue(result.length() > 0);
        assertNotEquals(existingEncodedList, result);

        Map<Long, Boolean> verificationMap = new HashMap<>();
        verificationMap.put(0L, false);
        String verificationResult = BitStringStatusListUtils.updateEncodedList(result, verificationMap, 16L);
        assertNotEquals(result, verificationResult);
    }

    @Test
    public void updateEncodedList_WithEmptyStatusMap_ReturnsEncodedString() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        Map<Long, Boolean> statusMap = new HashMap<>();

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 16L);

        assertNotNull(result);
        assertEquals(existingEncodedList, result);
    }

    @Test
    public void updateEncodedList_WithIndexOutOfBounds_LogsWarningAndContinues() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(200000L, true);
        statusMap.put(1L, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 16L);

        assertNotNull(result);
        assertNotEquals(existingEncodedList, result);

        Map<Long, Boolean> toggleMap = new HashMap<>();
        toggleMap.put(1L, false);
        String toggledResult = BitStringStatusListUtils.updateEncodedList(result, toggleMap, 16L);
        assertNotEquals(result, toggledResult);
    }

    @Test
    public void updateEncodedList_WithNegativeIndex_LogsWarningAndContinues() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(-1L, true);
        statusMap.put(1L, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 16L);

        assertNotNull(result);
        assertNotEquals(existingEncodedList, result);

        Map<Long, Boolean> toggleMap = new HashMap<>();
        toggleMap.put(1L, false);
        String toggledResult = BitStringStatusListUtils.updateEncodedList(result, toggleMap, 16L);
        assertNotEquals(result, toggledResult);
    }

    @Test(expected = CertifyException.class)
    public void updateEncodedList_WithNegativeCapacity_ThrowsCertifyException() {
        String existingEncodedList = "uH4sIAAAAAAAAA-sEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        Map<Long, Boolean> statusMap = new HashMap<>();

        BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, -1L);
    }

    @Test(expected = CertifyException.class)
    public void updateEncodedList_WithExcessiveCapacity_ThrowsCertifyException() {
        String existingEncodedList = "uH4sIAAAAAAAAA-sEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        Map<Long, Boolean> statusMap = new HashMap<>();
        long excessiveCapacity = Long.MAX_VALUE / 8192L + 1;

        BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, excessiveCapacity);
    }

    @Test(expected = CertifyException.class)
    public void updateEncodedList_WithInvalidEncodedList_ThrowsCertifyException() {
        String invalidEncodedList = "invalid-base64-string";
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(1L, true);

        BitStringStatusListUtils.updateEncodedList(invalidEncodedList, statusMap, 16L);
    }

    @Test(expected = CertifyException.class)
    public void updateEncodedList_WithNullEncodedList_ThrowsCertifyException() {
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(1L, true);

        BitStringStatusListUtils.updateEncodedList(null, statusMap, 16L);
    }

    @Test(expected = CertifyException.class)
    public void updateEncodedList_WithEmptyEncodedList_ThrowsCertifyException() {
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(1L, true);

        BitStringStatusListUtils.updateEncodedList("", statusMap, 16L);
    }

    @Test
    public void createEmptyEncodedList_WithValidCapacity_ReturnsEncodedString() {
        String result = BitStringStatusListUtils.createEmptyEncodedList(16L);

        assertNotNull(result);
        assertTrue(result.startsWith("u"));
        assertTrue(result.length() > 1);
    }

    @Test
    public void createEmptyEncodedList_WithMinimumCapacity_ReturnsEncodedString() {
        String result = BitStringStatusListUtils.createEmptyEncodedList(0L);

        assertNotNull(result);
        assertTrue(result.startsWith("u"));
    }

    @Test
    public void createEmptyEncodedList_WithLargeValidCapacity_ReturnsEncodedString() {
        String result = BitStringStatusListUtils.createEmptyEncodedList(1024L);

        assertNotNull(result);
        assertTrue(result.startsWith("u"));
    }

    @Test(expected = CertifyException.class)
    public void createEmptyEncodedList_WithNegativeCapacity_ThrowsCertifyException() {
        BitStringStatusListUtils.createEmptyEncodedList(-1L);
    }

    @Test(expected = CertifyException.class)
    public void createEmptyEncodedList_WithExcessiveCapacity_ThrowsCertifyException() {
        long excessiveCapacity = Long.MAX_VALUE / 8192L + 1;

        BitStringStatusListUtils.createEmptyEncodedList(excessiveCapacity);
    }

    @Test
    public void createEmptyEncodedList_WithCapacityAtIntegerMaxValue_ReturnsEncodedString() {
        long capacityThatResultsInMaxInt = (Integer.MAX_VALUE / 8192L);

        String result = BitStringStatusListUtils.createEmptyEncodedList(capacityThatResultsInMaxInt);

        assertNotNull(result);
        assertTrue(result.startsWith("u"));
    }

    @Test(expected = CertifyException.class)
    public void createEmptyEncodedList_WithCapacityExceedingIntegerMaxValue_ThrowsCertifyException() {
        long capacityThatExceedsMaxInt = (Integer.MAX_VALUE / 8192L) + 1;

        BitStringStatusListUtils.createEmptyEncodedList(capacityThatExceedsMaxInt);
    }

    @Test
    public void updateEncodedList_WithMultipleStatusChanges_ReturnsUpdatedEncodedString() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(0L, true);
        statusMap.put(5L, true);
        statusMap.put(10L, false);
        statusMap.put(15L, true);
        statusMap.put(100L, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 16L);

        assertNotNull(result);
        assertNotEquals(existingEncodedList, result);

        for (Long index : statusMap.keySet()) {
            if (index < 16L * 8192L) {
                Map<Long, Boolean> toggleMap = new HashMap<>();
                toggleMap.put(index, !statusMap.get(index));
                String toggledResult = BitStringStatusListUtils.updateEncodedList(result, toggleMap, 16L);
                assertNotEquals("Bit at index " + index + " should have changed", result, toggledResult);
            }
        }
    }

    @Test
    public void updateEncodedList_WithEncodedListWithoutPrefix_ReturnsEncodedString() {
        String emptyEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);
        String encodedListWithoutPrefix = emptyEncodedList.substring(1);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(1L, true);

        String result = BitStringStatusListUtils.updateEncodedList(encodedListWithoutPrefix, statusMap, 16L);

        assertNotNull(result);
        assertNotEquals(emptyEncodedList, result);
    }

    @Test
    public void createEmptyEncodedList_ConsistentResults_ReturnsSameEncodedStringForSameCapacity() {
        String result1 = BitStringStatusListUtils.createEmptyEncodedList(32L);
        String result2 = BitStringStatusListUtils.createEmptyEncodedList(32L);

        assertEquals(result1, result2);
    }

    @Test
    public void updateEncodedList_WithZeroCapacity_UsesMinimumCapacity() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(0L);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(1000L, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, 0L);

        assertNotNull(result);
        assertNotEquals(existingEncodedList, result);

        Map<Long, Boolean> toggleMap = new HashMap<>();
        toggleMap.put(1000L, false);
        String toggledResult = BitStringStatusListUtils.updateEncodedList(result, toggleMap, 0L);
        assertNotEquals(result, toggledResult);
    }

    @Test
    public void updateEncodedList_OverwritingExistingStatus_ReturnsUpdatedString() {
        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(16L);

        Map<Long, Boolean> firstUpdate = new HashMap<>();
        firstUpdate.put(5L, true);
        String firstResult = BitStringStatusListUtils.updateEncodedList(existingEncodedList, firstUpdate, 16L);

        Map<Long, Boolean> secondUpdate = new HashMap<>();
        secondUpdate.put(5L, false);
        String secondResult = BitStringStatusListUtils.updateEncodedList(firstResult, secondUpdate, 16L);

        assertNotNull(secondResult);
        assertNotEquals(firstResult, secondResult);

        Map<Long, Boolean> thirdUpdate = new HashMap<>();
        thirdUpdate.put(5L, true);
        String thirdResult = BitStringStatusListUtils.updateEncodedList(secondResult, thirdUpdate, 16L);
        assertEquals("Setting bit back to original state should match first result", firstResult, thirdResult);
    }

    @Test
    public void updateEncodedList_WithBoundaryIndices_HandlesCorrectly() {
        long capacity = 16L;
        long maxValidIndex = (capacity * 8192L) - 1;

        String existingEncodedList = BitStringStatusListUtils.createEmptyEncodedList(capacity);
        Map<Long, Boolean> statusMap = new HashMap<>();
        statusMap.put(0L, true);
        statusMap.put(maxValidIndex, true);

        String result = BitStringStatusListUtils.updateEncodedList(existingEncodedList, statusMap, capacity);

        assertNotNull(result);
        assertNotEquals(existingEncodedList, result);

        Map<Long, Boolean> toggleMinMap = new HashMap<>();
        toggleMinMap.put(0L, false);
        String toggledMinResult = BitStringStatusListUtils.updateEncodedList(result, toggleMinMap, capacity);
        assertNotEquals("Minimum index bit should have changed", result, toggledMinResult);

        Map<Long, Boolean> toggleMaxMap = new HashMap<>();
        toggleMaxMap.put(maxValidIndex, false);
        String toggledMaxResult = BitStringStatusListUtils.updateEncodedList(result, toggleMaxMap, capacity);
        assertNotEquals("Maximum index bit should have changed", result, toggledMaxResult);
    }

    @Test
    public void updateEncodedList_BitPersistence_VerifiesStateChanges() {
        String emptyList = BitStringStatusListUtils.createEmptyEncodedList(16L);

        Map<Long, Boolean> setBits = new HashMap<>();
        setBits.put(1L, true);
        setBits.put(3L, true);
        setBits.put(7L, true);
        String listWithBitsSet = BitStringStatusListUtils.updateEncodedList(emptyList, setBits, 16L);

        Map<Long, Boolean> clearBit = new HashMap<>();
        clearBit.put(3L, false);
        String listWithBitCleared = BitStringStatusListUtils.updateEncodedList(listWithBitsSet, clearBit, 16L);

        Map<Long, Boolean> setBitAgain = new HashMap<>();
        setBitAgain.put(3L, true);
        String listWithBitSetAgain = BitStringStatusListUtils.updateEncodedList(listWithBitCleared, setBitAgain, 16L);

        assertNotEquals("Empty list should differ from list with bits set", emptyList, listWithBitsSet);
        assertNotEquals("List with bit cleared should differ from original set list", listWithBitsSet, listWithBitCleared);
        assertEquals("Setting bit again should restore original state", listWithBitsSet, listWithBitSetAgain);
    }

    @Test
    public void updateEncodedList_SingleBitToggle_ProducesExpectedResults() {
        String emptyList = BitStringStatusListUtils.createEmptyEncodedList(16L);

        Map<Long, Boolean> setBit = new HashMap<>();
        setBit.put(0L, true);
        String firstBitSet = BitStringStatusListUtils.updateEncodedList(emptyList, setBit, 16L);

        setBit.put(1L, true);
        String secondBitSet = BitStringStatusListUtils.updateEncodedList(firstBitSet, setBit, 16L);

        Map<Long, Boolean> clearBit = new HashMap<>();
        clearBit.put(0L, false);
        String firstBitCleared = BitStringStatusListUtils.updateEncodedList(secondBitSet, clearBit, 16L);

        assertNotEquals("Setting first bit should change empty list", emptyList, firstBitSet);
        assertNotEquals("Setting second bit should change result", firstBitSet, secondBitSet);
        assertNotEquals("Clearing first bit should change result", secondBitSet, firstBitCleared);

        Map<Long, Boolean> clearSecondBit = new HashMap<>();
        clearSecondBit.put(1L, false);
        String backToEmpty = BitStringStatusListUtils.updateEncodedList(firstBitCleared, clearSecondBit, 16L);
        assertEquals("Clearing all bits should return to empty state", emptyList, backToEmpty);
    }
}
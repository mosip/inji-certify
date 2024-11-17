package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;
import junit.framework.TestCase;
import org.apache.commons.validator.Arg;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.stream.Stream;

public class CredentialUtilsTest {

    @Test
    public void testGetTemplateName() {
        VCRequestDto request = new VCRequestDto();
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/Person.json"));
        request.setType(List.of("VerifiableCredential", "UniversityCredential"));
        String expected = "UniversityCredential,VerifiableCredential:https://example.org/Person.json,https://www.w3.org/ns/credentials/v2";
        Assert.assertEquals(expected, CredentialUtils.getTemplateName(request));
    }

    @ParameterizedTest
    @MethodSource("provideTimeDuration")
    public void testToSeconds(long expectedDuration, String duration) {
        Assert.assertEquals(expectedDuration, CredentialUtils.toSeconds(duration));
    }

    private static Stream<Arguments> provideTimeDuration() {
        return Stream.of(
                Arguments.of(14519, "4h1m59s"),
                Arguments.of(59, "59s"),
                Arguments.of(3_15_56_952, "1y"),
                Arguments.of(60, "1m"),
                Arguments.of(86400, "1d"),
                Arguments.of(6_31_13_904, ""),
                Arguments.of(6_31_13_904, "0s")
        );
    }
}
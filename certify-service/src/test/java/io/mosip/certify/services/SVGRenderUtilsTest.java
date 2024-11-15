package io.mosip.certify.services;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SVGRenderUtilsTest {

    @Test
    void getDigestMultibase() {
        String svg = """
               <svg viewBox=".5 .5 3 4" fill="none" stroke="#20b2a" stroke-linecap="round"> <path d=" M1 4h-.001 V1h2v.001 M1 2.6 h1v.001"/> </svg>
                """;
        String actual = SVGRenderUtils.getDigestMultibase(svg);
        String expected = "z4po9QkJj1fhMt6cxHSnDnAUat4PEVrerUGGsPHLxJnK5";
        assertEquals(expected, actual);
    }

}
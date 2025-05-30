package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CredentialUtils {
    // returns true for VC 2.0 VCI requests
    public static boolean isVC2_0Request(VCRequestDto r) {
        return r.getContext().get(0).equals("https://www.w3.org/ns/credentials/v2");
    }

    /**
     * get the template name for a VCRequest for VCFormatter lib
     * @param vcRequestDto
     * @return
     */
    public static String getTemplateName(VCRequestDto vcRequestDto) {
        List<String> c = new ArrayList<>(vcRequestDto.getContext());
        List<String> t = new ArrayList<>(vcRequestDto.getType());
        Collections.sort(c);
        Collections.sort(t);
        String contextKey = String.join(",", c);
        String typeKey = String.join(",", t);
        String temp = String.join(":", typeKey, contextKey);
        return String.join(":", typeKey, contextKey);
    }
}

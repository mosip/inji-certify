package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;

public class CredentialUtils {
    // returns true for VC 2.0 VCI requests
    public static boolean isVC2_0Request(VCRequestDto r) {
        return r.getContext().get(0).equals("https://www.w3.org/ns/credentials/v2");
    }

    // DO NOT USE NOW
    public static boolean isNextGenPluginRequest(VCRequestDto r) {
        // TODO: Check the Spring Config values and verify if request should be handled by
        //  VCIssuancePlugin or the newer type of plugin.
        // TODO: use the Host header + credential.type
        return true;
    }
}

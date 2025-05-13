package io.mosip.certify.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.core.constants.Constants;

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
        //TODO: Cache this entire data so we do not construct all the time.
        List<String> c = new ArrayList<>(vcRequestDto.getContext());
        List<String> t = new ArrayList<>(vcRequestDto.getType());
        Collections.sort(c);
        Collections.sort(t);
        String contextKey = String.join(",", c);
        String typeKey = String.join(",", t);
      //  contextKey = StringUtils.hasText(vcRequestDto.getFormat())?contextKey.concat("-"+vcRequestDto.getFormat()):contextKey;
        return String.join(Constants.DELIMITER, typeKey, contextKey,vcRequestDto.getFormat());
    }
}

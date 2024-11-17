package io.mosip.certify.utils;

import io.mosip.certify.api.dto.VCRequestDto;

import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CredentialUtils {
    public static final long DEFAULT_EXPIRY_DURATION_SECONDS = 2 * ChronoUnit.YEARS.getDuration().getSeconds();
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
        return String.join(":", typeKey, contextKey);
    }

    /**
     * Converts a String time duration to seconds
     * @param duration
     * @return
     */
    public static long toSeconds(String duration) {
        Pattern pattern = Pattern.compile("(?:(\\d+)y)?(?:(\\d+)M)?(?:(\\d+)d)?(?:(\\d+)h)?(?:(\\d+)m)?(?:(\\d+)s)?");
        Matcher matcher = pattern.matcher(duration);
        long total = 0;
        TemporalUnit[] durationArray = {ChronoUnit.YEARS, ChronoUnit.MONTHS, ChronoUnit.DAYS, ChronoUnit.HOURS, ChronoUnit.MINUTES, ChronoUnit.SECONDS };
        if (matcher.matches()) {
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) {
                    total += Integer.parseInt(matcher.group(i)) * durationArray[i-1].getDuration().getSeconds();
                }
            }
            if (total == 0) {
                return DEFAULT_EXPIRY_DURATION_SECONDS;
            }
            return total;
        }
        return DEFAULT_EXPIRY_DURATION_SECONDS;
    }
}

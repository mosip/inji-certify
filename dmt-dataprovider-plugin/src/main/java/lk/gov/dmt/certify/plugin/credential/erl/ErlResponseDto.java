package lk.gov.dmt.certify.plugin.credential.erl;

import lk.gov.dmt.certify.plugin.model.VcData;
import lk.gov.dmt.certify.plugin.validation.TextValidation;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Map;

import static lk.gov.dmt.certify.plugin.error.DmtExchangeErrors.*;

public record ErlResponseDto(String vehicleNo, String chassisNo, LocalDate issueDate, LocalDate expireDate) {
    public ErlResponseDto {
        if (!validIdentifier(vehicleNo) || !validIdentifier(chassisNo) || issueDate == null
                || expireDate == null || expireDate.isBefore(issueDate)) {
            throw new IllegalArgumentException("Invalid ERL response fields");
        }
    }

    static ErlResponseDto parse(JsonNode node) throws ExchangeFailure {
        if (node == null || !node.isObject()) throw error(Failure.INVALID_RESPONSE);
        try {
            return new ErlResponseDto(field(node, "vehicleNo"), field(node, "chassisNo"),
                    LocalDate.parse(field(node, "issueDate")), LocalDate.parse(field(node, "expireDate")));
        } catch (IllegalArgumentException | DateTimeParseException e) {
            // Do not retain parse exceptions containing personal data from the response.
            throw error(Failure.INVALID_RESPONSE);
        }
    }

    private static String field(JsonNode node, String key) {
        JsonNode value = node.get(key);
        if (value == null || !value.isTextual()) throw new IllegalArgumentException("Missing ERL field");
        return value.textValue();
    }

    private static boolean validIdentifier(String value) {
        return TextValidation.text(value) && value.length() <= 128
                && !TextValidation.controls(value);
    }

    public VcData toVcData() {
        return new VcData(Map.of("vehicleNo", vehicleNo, "chassisNo", chassisNo,
                "issueDate", issueDate.toString(), "expireDate", expireDate.toString()));
    }

    @Override
    public String toString() { return "ErlResponseDto[fields=<redacted>]"; }
}

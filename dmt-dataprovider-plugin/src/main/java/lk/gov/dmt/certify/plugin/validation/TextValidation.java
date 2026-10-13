package lk.gov.dmt.certify.plugin.validation;

/** Shared checks for untrusted textual values. */
public final class TextValidation {
    private TextValidation() {}

    public static boolean text(String value) { return value != null && !value.isBlank(); }

    public static boolean controls(String value) {
        return value.codePoints().anyMatch(Character::isISOControl);
    }

    public static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
}

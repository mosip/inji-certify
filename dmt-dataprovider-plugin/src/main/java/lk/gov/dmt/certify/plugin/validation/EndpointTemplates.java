package lk.gov.dmt.certify.plugin.validation;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Validates deployment-controlled endpoint paths and their named variables. */
public final class EndpointTemplates {
    private static final Pattern PATH_VARIABLE = Pattern.compile("\\{([a-z][a-zA-Z0-9]*)\\}");

    private EndpointTemplates() {}

    public static Set<String> variables(String path) {
        TextValidation.require(TextValidation.text(path) && path.startsWith("/")
                && !path.startsWith("//"), "Endpoint must be an absolute path on the configured origin");
        TextValidation.require(path.matches("(?:/(?:[a-zA-Z0-9_-]+|\\{[a-z][a-zA-Z0-9]*\\}))+/?"),
                "Invalid endpoint path or variable");
        Set<String> variables = new HashSet<>();
        var matcher = PATH_VARIABLE.matcher(path);
        while (matcher.find()) {
            TextValidation.require(variables.add(matcher.group(1)), "Duplicate endpoint variable");
        }
        TextValidation.require(!variables.isEmpty(), "Endpoint requires a named lookup variable");
        return Set.copyOf(variables);
    }
}

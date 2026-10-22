package io.mosip.certify.utils;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SDJsonUtils {

    // Possessive quantifiers: a greedy repeated group recurses once per segment in
    // java.util.regex and overflows the stack on a long enough path. The segments start
    // with distinct characters, so nothing ever needs to backtrack and the accepted paths
    // are unchanged.
    private static final Pattern SD_PATH_SYNTAX =
            Pattern.compile("^\\$(?:\\.[^.\\[\\]]++|\\[(?:\\*|0|[1-9]\\d*+)\\])*+$");

    /**
     * This method constructs the SD-JWT payload for a given JSON node.
     * <p>
     * It will recursively handle nested objects and arrays.
     *
     * @param node The JSON node to start the walk.
     * @param sdObjectBuilder The final builder object. This object contains the final SD-JWT payload.
     * @param sdPaths The list of path that needs to be converted as a SD Claim.
     * @param currentPath The current path of the JsonNode, for eg: use $ as the begining.
     */
    public static void constructSDPayload(JsonNode node, SDObjectBuilder sdObjectBuilder, List<Disclosure> disclosures, List<String> sdPaths, String currentPath) {
        boolean isSDPath = anyMatch(currentPath, sdPaths);

        if (node.isObject()) {
            if(isSDPath){
               Disclosure disclosure = sdObjectBuilder.putSDClaim(getLeafNodeName(currentPath), buildObjectMap(node));
               disclosures.add(disclosure);
                return; //fix this
            }

            SDObjectBuilder internalSD = new SDObjectBuilder();
            Iterator<String> fieldNames = node.fieldNames();
            while (fieldNames.hasNext()) {
                String fieldName = fieldNames.next();
                if(!node.get(fieldName).isObject() && !node.get(fieldName).isArray()){
                    buildSimpleClaim(node.get(fieldName), sdObjectBuilder, disclosures, currentPath + "." + fieldName,anyMatch(currentPath + "." + fieldName, sdPaths));
                    continue;
                }
                if(node.isObject() && anyMatch(currentPath + "." + fieldName, sdPaths)){
                    constructSDPayload(node.get(fieldName), sdObjectBuilder, disclosures, sdPaths, currentPath + "." + fieldName);
                    continue;
                }

                if(node.get(fieldName).isArray()){
                    constructSDPayload(node.get(fieldName), internalSD, disclosures, sdPaths, currentPath + "." + fieldName);
                    if (internalSD.build().get(fieldName) == null ) {
                        sdObjectBuilder.putClaim(fieldName, internalSD.build());
                    } else sdObjectBuilder.putClaim(fieldName, internalSD.build().get(fieldName));
                    internalSD = new SDObjectBuilder();
                    continue;
                }
                constructSDPayload(node.get(fieldName), internalSD, disclosures, sdPaths, currentPath + "." + fieldName);
                sdObjectBuilder.putClaim(fieldName, internalSD.build());
                internalSD = new SDObjectBuilder();//reinitialize for the next round.
            }
            
        } else if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            buildArrayClaim(arrayNode, sdObjectBuilder, disclosures, sdPaths, currentPath);
        } else {
            buildSimpleClaim(node, sdObjectBuilder, disclosures, currentPath, isSDPath);
        }
    }

     /**
     * This method compares the given path with the list of paths . 
     * It expects both the path have same number of '.'
     * @param path The path to compare.
     * @param paths The list of paths to compare.
     * @return true if found a match handles array with index and *
     */
    public static boolean anyMatch(String path, List<String> paths){
        for(int i = 0; i < paths.size(); i++){
            if (compareJsonPaths(path, paths.get(i)) == true) 
                return true;
        }
        return false;
    }

     /**
     * This method compares two paths (path1, path2). 
     * It expects both the path have same number of '.'
     * @param path1 The first path to compare.
     * @param path2 The second path to compare.
     * @return Converted Map for the given JsonNode.
     */
    public static boolean compareJsonPaths(String path1, String path2) {
        // Split the paths into segments by "."
        path1 = path1.trim();
        path2 = path2.trim();
        String[] parts1 = path1.split("\\.");
        String[] parts2 = path2.split("\\.");

        // If the number of segments is different, the paths don't match
        if (parts1.length != parts2.length) {
            return false;
        }

        // Iterate through each segment and compare
        for (int i = 0; i < parts1.length; i++) {
            String part1 = parts1[i];
            String part2 = parts2[i];

            // Handle wildcard (*) match
            if (part1.equals("*") || part2.equals("*")) continue;

            if(part1.equals(part2)) continue;

            // Handle array index match
            if (part1.endsWith("]") && part2.endsWith("]")) {
                String pattern = part2.replace("[*]", "\\[\\d+\\]");
                if (part1.matches(pattern)) {
                    continue;
                }
            }

            // If the segments are not the same and neither is a wildcard, they don't match
            if (!part1.equals(part2)) {
                return false;
            }
        }

        // If all segments match or are wildcards, return true
        return true;
    }
    
    /**
     * This method builds the array claims in the SD-JWT payload for a given JSON node.
     * <p>
     * It will recursively handle nested objects and nested arrays.
     *
     * @param node The JSON node to start the walk.
     * @param sdObjectBuilder The final builder object. This object contains the final SD-JWT payload.
     * @param sdPaths The list of path that needs to be converted as a SD Claim.
     * @param currentPath The current path of the JsonNode, for eg: use $ as the begining.
     */

    private static void buildArrayClaim(ArrayNode arrayNode, SDObjectBuilder sdObjectBuilder, List<Disclosure> disclosures, List<String> sdPaths , String currentPath){
        ArrayList<Object> arrayList = new ArrayList<>();
        //if the whole array is asked to be SD.
        if(anyMatch(currentPath, sdPaths)){
            //Convert to array and add
            ObjectMapper objectMapper = new ObjectMapper();
            for (JsonNode dataNode : arrayNode) { 
                try{
                    arrayList.add(objectMapper.treeToValue(dataNode, Object.class));
                }
                catch(JsonProcessingException jpe){
                    //Lets just swallow this and move on as this error may never occur. Even if it occurs we should not worry..
                    log.error("Error processing " + currentPath + " ", jpe);
                }
            }
           // Disclosure d = new Disclosure(arrayList);
            Disclosure disclosure = sdObjectBuilder.putSDClaim(getLeafNodeName(currentPath),arrayList);
            disclosures.add(disclosure);
            return;
        } 
        for (int i = 0; i < arrayNode.size(); i++) {
            boolean isSDPath = anyMatch(currentPath+"["+i+"]", sdPaths);
            if(arrayNode.get(i).isObject() || arrayNode.get(i).isArray()){
                SDObjectBuilder internalSDBuilder = new SDObjectBuilder();
                constructSDPayload(arrayNode.get(i), internalSDBuilder, disclosures, sdPaths, currentPath+"["+i+"]");
                arrayList.add(internalSDBuilder.build());
            }
            else if (isSDPath){
                Disclosure disclosure = new Disclosure(arrayNode.get(i));
                arrayList.add(disclosure.toArrayElement());
            }
            else {
                arrayList.add(arrayNode.get(i));
            }
        }
        sdObjectBuilder.putClaim(getLeafNodeName(currentPath), arrayList);

    }

    /**
     * This method builds the map object for a given JsonNode.
     *
     * @param node The JSON node to start the walk.
     * @return Converted Map for the given JsonNode.
     */

    private static  Map<String, Object> buildObjectMap(JsonNode node){
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = mapper.convertValue(node, Map.class);
        return map;
    }

     /**
     * This method builds the simple claims in the SD-JWT payload for a given JSON node.
     * <p>
     * for eg: will handle the key and value pair.
     *
     * @param node The JSON node to start the walk.
     * @param sdObjectBuilder The builder object. This object contains the simple claim SD-JWT payload for the given node.
     * @param currentPath The current path of the JsonNode, for eg: use $ as the begining.
     * @param isSDPath a boolean indicating if the given node is an 
     */
    private static void buildSimpleClaim(JsonNode node, SDObjectBuilder sdObjectBuilder, List<Disclosure> disclosures, String currentPath, boolean isSDPath){
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            Object value = objectMapper.treeToValue(node, Object.class);
                 
            if (isSDPath){
                Disclosure disclosure = sdObjectBuilder.putSDClaim(getLeafNodeName(currentPath), value);
                disclosures.add(disclosure);
                return;
            }
            sdObjectBuilder.putClaim(getLeafNodeName(currentPath), value);
        } catch (JsonProcessingException jpe) {
            log.error("Error processing {}", currentPath, jpe);
        }
    }

    /**
     * The field names along a selective disclosure path, with array indexes dropped:
     * {@code $.address.city} is {@code [address, city]} and {@code $.people[*].name} is
     * {@code [people, name]}. Empty for {@code $}.
     */
    static List<String> getPathFields(String path) {
        List<String> fields = new ArrayList<>();
        for (String segment : path.trim().replaceAll("\\[[^\\]]*\\]", "").split("\\.")) {
            if (!segment.isEmpty() && !segment.equals("$")) {
                fields.add(segment);
            }
        }
        return fields;
    }

    /** Field-by-field comparison where a {@code *} in the path matches any one key at that level. */
    private static boolean matchesPath(List<String> declared, List<String> target) {
        if (declared.size() != target.size()) {
            return false;
        }
        for (int i = 0; i < target.size(); i++) {
            if (!target.get(i).equals("*") && !target.get(i).equals(declared.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether the raw VC template declares this path: each of its fields as a JSON key, nested under
     * the one before it. Array levels are skipped, as they are in the path, and a {@code *} field
     * matches any key at its level.
     *
     * <p>The template is Velocity, not JSON, so it is scanned rather than parsed. Directives such as
     * {@code #if} contain no braces, so a key inside a conditional block counts as declared, and the
     * braces of {@code ${...}}, {@code $!{...}} and {@code #{...}} are skipped along with comments.
     *
     * @return {@code false} for {@code $}, which names no field
     */
    public static boolean isPathInTemplate(String template, String path) {
        if (template == null || path == null) {
            return false;
        }
        List<String> target = getPathFields(path);
        if (target.isEmpty()) {
            return false;
        }
        Deque<String> parents = new ArrayDeque<>();   // key that opened each enclosing {/[; "" when none
        String pendingKey = null;
        int n = template.length();
        for (int i = 0; i < n; i++) {
            char c = template.charAt(i);
            if (c == '"') {
                int end = i + 1;
                StringBuilder value = new StringBuilder();
                while (end < n && template.charAt(end) != '"') {
                    if (template.charAt(end) == '\\' && end + 1 < n) {
                        end++;
                    }
                    value.append(template.charAt(end));
                    end++;
                }
                i = end;
                int next = i + 1;
                while (next < n && Character.isWhitespace(template.charAt(next))) {
                    next++;
                }
                if (next < n && template.charAt(next) == ':') {
                    pendingKey = value.toString();
                    List<String> current = new ArrayList<>();
                    parents.descendingIterator().forEachRemaining(key -> {
                        if (!key.isEmpty()) {
                            current.add(key);
                        }
                    });
                    current.add(pendingKey);
                    if (matchesPath(current, target)) {
                        return true;
                    }
                }
            } else if ((c == '$' || c == '#') && i + 1 < n
                    && (template.charAt(i + 1) == '{' || (template.charAt(i + 1) == '!' && i + 2 < n && template.charAt(i + 2) == '{'))) {
                i = findReferenceEnd(template, template.charAt(i + 1) == '{' ? i + 1 : i + 2);
            } else if (c == '#' && i + 1 < n && template.charAt(i + 1) == '#') {
                int eol = template.indexOf('\n', i);
                i = eol < 0 ? n : eol;
            } else if (c == '#' && i + 1 < n && template.charAt(i + 1) == '*') {
                int close = template.indexOf("*#", i + 2);
                i = close < 0 ? n : close + 1;
            } else if (c == '{' || c == '[') {
                parents.push(pendingKey == null ? "" : pendingKey);
                pendingKey = null;
            } else if (c == '}' || c == ']') {
                if (!parents.isEmpty()) {
                    parents.pop();
                }
                pendingKey = null;
            } else if (c == ',') {
                pendingKey = null;
            }
        }
        return false;
    }

    /**
     * The index of the brace that closes the Velocity reference opened at {@code open}. Braces nested in
     * its arguments are counted and its string literals skipped, so neither ends it early.
     *
     * @return the template length when the reference never closes
     */
    private static int findReferenceEnd(String template, int open) {
        int n = template.length();
        int depth = 0;
        for (int i = open; i < n; i++) {
            char c = template.charAt(i);
            if (c == '"' || c == '\'') {
                int close = template.indexOf(c, i + 1);
                if (close < 0) {
                    return n;
                }
                i = close;
            } else if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return i;
            }
        }
        return n;
    }

    /**
     * Whether a selective disclosure path is well formed: {@code $} followed by {@code .field} and
     * {@code [index]} or {@code [*]} segments. Says nothing about whether the path exists in a credential.
     */
    public static boolean isPathSyntaxValid(String path) {
        return path != null && SD_PATH_SYNTAX.matcher(path.trim()).matches();
    }

    /**
     * Validates if a JSON path exists in a given JsonNode.
     *
     * @param root The root JsonNode.
     * @param path The JSON path to validate (e.g. $.credentialSubject.name, $.hobbies[*])
     * @return true if the path exists, false otherwise.
     */
    public static boolean isPathValid(JsonNode root, String path) {
        String[] segments = toSegments(path);
        if (segments == null) {
            return false;
        }
        return segments.length == 0 || checkSegments(root, segments, 0);
    }

    /**
     * Splits a well-formed path into the segments the walkers below expect: {@code $.a[0].b} is
     * {@code [a, [0], b]}.
     *
     * @return the segments, empty for {@code $}, or {@code null} when the path is malformed
     */
    private static String[] toSegments(String path) {
        if (path == null || path.trim().isEmpty()) {
            return null;
        }
        path = path.trim();
        if (!isPathSyntaxValid(path) || path.contains("..")) {
            return null;
        }
        if (path.startsWith("$")) {
            path = path.substring(1);
        }
        if (path.startsWith(".")) {
            path = path.substring(1);
        }
        if (path.isEmpty()) {
            return new String[0];
        }
        String normalizedPath = path.replace("[", ".[");
        if (normalizedPath.startsWith(".")) {
            normalizedPath = normalizedPath.substring(1);
        }
        return normalizedPath.split("\\.");
    }

    private enum PathState { PRESENT, ABSENT, MISMATCH }

    /**
     * Whether a path is missing from a credential only because the data is not there: a key that is
     * absent or null, or an array or object that is empty. Such a path may be an optional field.
     *
     * <p>A value that is present but has a different shape, such as a string where the path expects an
     * array ({@code $.name[*]} with a scalar {@code name}), is not absent. Treating it as optional would
     * issue that value as an ordinary claim instead of a selectively disclosable one.
     *
     * @return {@code true} only when every way the path could resolve ends in missing data
     */
    public static boolean isPathAbsent(JsonNode root, String path) {
        String[] segments = toSegments(path);
        return segments != null && segments.length > 0 && walk(root, segments, 0) == PathState.ABSENT;
    }

    private static PathState walk(JsonNode node, String[] segments, int index) {
        if (index >= segments.length) {
            return PathState.PRESENT;
        }
        if (node == null || node.isMissingNode() || node.isNull()) {
            return PathState.ABSENT;
        }
        String segment = segments[index];
        if (segment.startsWith("[") && segment.endsWith("]")) {
            if (!node.isArray()) {
                return PathState.MISMATCH;
            }
            String indexStr = segment.substring(1, segment.length() - 1);
            if (indexStr.equals("*")) {
                return walkEach(node, segments, index);
            }
            try {
                int arrayIdx = Integer.parseInt(indexStr);
                return arrayIdx < node.size() ? walk(node.get(arrayIdx), segments, index + 1) : PathState.ABSENT;
            } catch (NumberFormatException e) {
                return PathState.ABSENT;   // an index too large for an int is past the end of any array
            }
        }
        if (!node.isObject()) {
            return PathState.MISMATCH;
        }
        if (segment.equals("*")) {
            return walkEach(node, segments, index);
        }
        return node.has(segment) ? walk(node.get(segment), segments, index + 1) : PathState.ABSENT;
    }

    /** A wildcard over a container: any mismatch wins, then any match; an empty container is absent. */
    private static PathState walkEach(JsonNode container, String[] segments, int index) {
        PathState result = PathState.ABSENT;
        for (JsonNode child : container) {
            PathState state = walk(child, segments, index + 1);
            if (state == PathState.MISMATCH) {
                return PathState.MISMATCH;
            }
            if (state == PathState.PRESENT) {
                result = PathState.PRESENT;
            }
        }
        return result;
    }

    private static boolean checkSegments(JsonNode node, String[] segments, int index) {
        if (index >= segments.length) {
            return true;
        }
        if (node == null || node.isMissingNode()) {
            return false;
        }
        if (node.isNull()) {
            return false;
        }

        String segment = segments[index];
        if (segment.startsWith("[") && segment.endsWith("]")) {
            if (!node.isArray()) {
                return false;
            }
            String indexStr = segment.substring(1, segment.length() - 1);
            if (indexStr.equals("*")) {
                if (node.size() == 0) {
                    return false;
                }
                for (JsonNode element : node) {
                    if (checkSegments(element, segments, index + 1)) {
                        return true;
                    }
                }
                return false;
            } else {
                try {
                    int arrayIdx = Integer.parseInt(indexStr);
                    if (arrayIdx < 0 || arrayIdx >= node.size()) {
                        return false;
                    }
                    return checkSegments(node.get(arrayIdx), segments, index + 1);
                } catch (NumberFormatException e) {
                    return false;
                }
            }
        } else {
            if (!node.isObject()) {
                return false;
            }
            if (segment.equals("*")) {
                if (node.size() == 0) {
                    return false;
                }
                for (JsonNode child : node) {
                    if (checkSegments(child, segments, index + 1)) {
                        return true;
                    }
                }
                return false;
            }
            if (!node.has(segment)) {
                return false;
            }
            return checkSegments(node.get(segment), segments, index + 1);
        }
    }

    /**
     * Extracts the leaf node name from the given JSONPath string.
     *
     * @param jsonPath The JSONPath string (e.g., $.store.book[0].author)
     * @return The leaf node name or null if not found or an error occurs
     */
    public static String getLeafNodeName(String jsonPath) {
        if (jsonPath == null || jsonPath.trim().isEmpty()) {
            log.error("JSON path cannot be null or empty.");
            return null;
        }

        // Normalize the JSONPath: strip leading '$.' and split by '.' and '[index]'
        jsonPath = jsonPath.trim();
        if (jsonPath.startsWith("$.")) {
            jsonPath = jsonPath.substring(2);  // Remove leading "$."
        }

        String[] pathParts = jsonPath.split("\\.");
        String leafNodeName = null;

        try {
            for (String part : pathParts) {
                if (part.contains("[")) {
                    // Handle array part, e.g., book[0]
                    int indexStart = part.indexOf('[');
                    int indexEnd = part.indexOf(']');
                    if (indexStart != -1 && indexEnd != -1) {
                        // Get the array index and strip it
                        String arrayName = part.substring(0, indexStart); // e.g., book
                       
                        leafNodeName = arrayName; // Set the array name as the leaf node name
                    }
                } else {
                    // Handle object part (key name)
                    leafNodeName = part;
                }
            }
        } catch (Exception e) {
            log.error("Error parsing JSON path: ", e);
        }

        return leafNodeName;
    }
}

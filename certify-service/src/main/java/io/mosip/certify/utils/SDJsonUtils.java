package io.mosip.certify.utils;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SDJsonUtils {
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

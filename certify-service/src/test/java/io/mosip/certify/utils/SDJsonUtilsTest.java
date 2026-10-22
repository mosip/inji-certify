package io.mosip.certify.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

public class SDJsonUtilsTest {

    @Test
    public void testGetLeafNodeName() {

      String path1 = "$.store.book[0].author";  // Should return "author"
        String path2 = "$.store.bicycle.color";  // Should return "color"
        String path3 = "$.store.book[1].title";  // Should return "title"
        String path4 = "$.store.book[0]";        // Should return "book"

        assertEquals("author", SDJsonUtils.getLeafNodeName(path1));
        assertEquals("color", SDJsonUtils.getLeafNodeName(path2));
        assertEquals("title", SDJsonUtils.getLeafNodeName(path3));
        assertEquals("book", SDJsonUtils.getLeafNodeName(path4));      
    }

    @Test
    public void testCompareJsonPaths() {
      String path1 = "$.store.book.author";
      String path2 = "$.store.book.author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book.*";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book.title";
      assertFalse(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book.*";
      path2 = "$.store.book.*";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[0].author";
      path2 = "$.store.book[0].author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path2 = "$.store.book[1].author";
      assertFalse(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[0].author";
      path2 = "$.store.book[0].*";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book.author";
      path2 = "$.store.*.author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path2 = "$.store.book[0].author";
      assertFalse(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$";
      path2 = "$";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[0].author";
      path2 = "$.store.book[*].author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[0";
      path2 = "$.store.book[0]";
      assertFalse(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book.author ";
      path2 = " $.store.book.author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.*.author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
    }

    @Test
    public void testConstructSDPayload(){
      // Create the input JSONNode from the provided JSON
      ObjectNode node = JsonNodeFactory.instance.objectNode();
      node.put("name", "John");
      node.put("dob", "2000-10-31");
      node.put("is_above_18", true);
      node.put("is_above_21", true);
      node.put("is_above_50", false);
      node.put("is_above_55", false);
      node.put("is_above_58", false);
      node.put("is_above_60", false);
      node.put("is_above_62", false);
      node.put("is_above_65", false);
      node.put("is_above_67", false);

      ArrayNode luckyNumberNode = JsonNodeFactory.instance.arrayNode();
      luckyNumberNode.add(251);
      luckyNumberNode.add(252);
      node.set("lucky_numbers",luckyNumberNode); //just for testing

      ArrayNode luckyCharacterNode = JsonNodeFactory.instance.arrayNode();
      luckyCharacterNode.add('A');
      luckyCharacterNode.add('B');
      node.set("lucky_characters",luckyCharacterNode); //just for testing
     
      // Create and set nested address object
      ObjectNode geoLocation = JsonNodeFactory.instance.objectNode();
      geoLocation.put("latitude", "11.004556");
      geoLocation.put("longitude", "76.961632");

      // Create and set nested address object
      ObjectNode addressNode = JsonNodeFactory.instance.objectNode();
      addressNode.put("street", "123 My St");
      addressNode.put("city", "Coimbatore");
      addressNode.put("pincode","641047");
      addressNode.put("geo", geoLocation);
      node.set("address", addressNode);

      // Create and set phoneNumbers array
      ArrayNode phoneNumbersNode = JsonNodeFactory.instance.arrayNode();
      ObjectNode homePhone = JsonNodeFactory.instance.objectNode();
      homePhone.put("type", "home");
      homePhone.put("number", "123-4567");
      phoneNumbersNode.add(homePhone);
      ObjectNode mobilePhone = JsonNodeFactory.instance.objectNode();
      mobilePhone.put("type", "mobile");
      mobilePhone.put("number", "987-6543");
      phoneNumbersNode.add(mobilePhone);
      node.set("phoneNumbers", phoneNumbersNode);

      // Initialize SDObjectBuilder and the list of SDPaths
      SDObjectBuilder sdObjectBuilder = new SDObjectBuilder();
      List<String> sdPaths = Arrays.asList("$.address.street","$.address.pincode","$.address.geo","$.dob","$.is_above_18","$.phoneNumbers[0].number","$.lucky_numbers","$.lucky_characters[1]");
      String currentPath = "$";
      List<Disclosure> disclosures = new ArrayList<>();
      SDJsonUtils.constructSDPayload(node, sdObjectBuilder, disclosures, sdPaths, currentPath);
      System.out.println(sdObjectBuilder.build());
      Map<String,Object> sdClaims = sdObjectBuilder.build();
      // Map<String, Object> payload = new java.util.HashMap<>();
      //   payload.put("name", "John");
      //   payload.put("age", 30);
      try {
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(sdClaims);
        // JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        //         .claim("name", payload.get("name"))
        //         .claim("age", payload.get("age"))
        //         .build();
        JWSHeader header =
            new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("dc+sd-jwt")).build();
        // Create a credential JWT. (not signed yet)
        SignedJWT jwt = new SignedJWT(header, claimsSet);

        // Create a private key to sign the credential JWT.
        ECKey privateKey = new ECKeyGenerator(Curve.P_256).generate();

        // Create a signer that signs the credential JWT with the private key.
        JWSSigner signer = new ECDSASigner(privateKey);

        // Let the signer sign the credential JWT.
        jwt.sign(signer);
        System.out.println(privateKey.toPublicJWK());
        System.out.println(jwt.serialize());
        SDJWT sdJwt = new SDJWT(jwt.serialize(), disclosures);
        System.out.println(sdJwt);
      } catch(Exception ex){
        ex.printStackTrace();
        fail("Exception occurred: " + ex.getMessage());
      }
        // Print the JWT in the JWS compact serialization format.
       

      // Assert the results
      // Verify that the SDObjectBuilder contains claims for the address and phoneNumbers
      //assertFalse(sdObjectBuilder.);

      // Check claims for address fields
      assertTrue(sdClaims.containsKey("address"));
      assertFalse(((Map<String, Object>)sdClaims.get("address")).containsKey("street"));
      assertTrue(((Map<String, Object>)sdClaims.get("address")).containsKey("city"));

      // Check claims for phoneNumbers array
      assertTrue(sdClaims.containsKey("phoneNumbers"));
      ArrayList<Object> phoneNumbers = (ArrayList<Object>) sdClaims.get("phoneNumbers");
      assertEquals(2, phoneNumbers.size());
      Map<String, Object> homePhoneObject = (Map<String, Object>) phoneNumbers.get(0);
      Map<String, Object> mobilePhoneObject = (Map<String, Object>) phoneNumbers.get(1);
      assertTrue(homePhoneObject.containsKey("type"));
      assertFalse(homePhoneObject.containsKey("number"));
      assertTrue(mobilePhoneObject.containsKey("type"));
      assertTrue(mobilePhoneObject.containsKey("number"));
    }

  @Test
  public void testConstructSDPayload_WildcardPatterns(){
    // Create the input JSONNode from the provided JSON
    ObjectNode node = JsonNodeFactory.instance.objectNode();
    node.put("name", "John");
    node.put("dob", "2000-10-31");
    node.put("is_above_18", true);
    node.put("is_above_21", true);

    ArrayNode luckyNumberNode = JsonNodeFactory.instance.arrayNode();
    luckyNumberNode.add(251);
    luckyNumberNode.add(252);
    node.set("lucky_numbers",luckyNumberNode);

    ArrayNode luckyCharacterNode = JsonNodeFactory.instance.arrayNode();
    luckyCharacterNode.add('A');
    luckyCharacterNode.add('B');
    node.set("lucky_characters",luckyCharacterNode);

    // Create and set nested address object
    ObjectNode geoLocation = JsonNodeFactory.instance.objectNode();
    geoLocation.put("latitude", "11.004556");
    geoLocation.put("longitude", "76.961632");

    // Create and set nested address object
    ObjectNode addressNode = JsonNodeFactory.instance.objectNode();
    addressNode.put("street", "123 My St");
    addressNode.put("city", "Coimbatore");
    addressNode.put("pincode","641047");
    addressNode.put("geo", geoLocation);
    node.set("address", addressNode);

    // Create and set phoneNumbers array
    ArrayNode phoneNumbersNode = JsonNodeFactory.instance.arrayNode();
    ObjectNode homePhone = JsonNodeFactory.instance.objectNode();
    homePhone.put("type", "home");
    homePhone.put("number", "123-4567");
    phoneNumbersNode.add(homePhone);
    ObjectNode mobilePhone = JsonNodeFactory.instance.objectNode();
    mobilePhone.put("type", "mobile");
    mobilePhone.put("number", "987-6543");
    phoneNumbersNode.add(mobilePhone);
    node.set("phoneNumbers", phoneNumbersNode);

    // Initialize SDObjectBuilder and the list of SDPaths
    SDObjectBuilder sdObjectBuilder = new SDObjectBuilder();
    List<String> sdPaths = Arrays.asList("$.address.*","$.phoneNumbers[*].number","$.lucky_numbers","$.lucky_characters[*]");
    String currentPath = "$";
    List<Disclosure> disclosures = new ArrayList<>();
    SDJsonUtils.constructSDPayload(node, sdObjectBuilder, disclosures, sdPaths, currentPath);
    System.out.println(sdObjectBuilder.build());
    Map<String,Object> sdClaims = sdObjectBuilder.build();

    // Check claims for address fields
    assertTrue(sdClaims.containsKey("address"));
    assertFalse(((Map<String, Object>)sdClaims.get("address")).containsKey("street"));
    assertFalse(((Map<String, Object>)sdClaims.get("address")).containsKey("city"));


    // Check claims for phoneNumbers array
    assertTrue(sdClaims.containsKey("phoneNumbers"));
    ArrayList<Object> phoneNumbers = (ArrayList<Object>) sdClaims.get("phoneNumbers");
    assertEquals(2, phoneNumbers.size());
    Map<String, Object> homePhoneObject = (Map<String, Object>) phoneNumbers.get(0);
    Map<String, Object> mobilePhoneObject = (Map<String, Object>) phoneNumbers.get(1);
    assertTrue(homePhoneObject.containsKey("type"));
    assertFalse(homePhoneObject.containsKey("number"));
    assertTrue(mobilePhoneObject.containsKey("type"));
    assertFalse(mobilePhoneObject.containsKey("number"));
  }

  @Test
  public void should_validatePath_when_validAndInvalidPaths() {
      ObjectNode node = JsonNodeFactory.instance.objectNode();
      node.put("name", "John");
      node.putNull("middleName");
      ObjectNode addressNode = JsonNodeFactory.instance.objectNode();
      addressNode.put("city", "Coimbatore");
      node.set("address", addressNode);

      ArrayNode emptyArray = JsonNodeFactory.instance.arrayNode();
      node.set("emptyList", emptyArray);

      ObjectNode emptyObj = JsonNodeFactory.instance.objectNode();
      node.set("emptyObj", emptyObj);

      ArrayNode listWithItems = JsonNodeFactory.instance.arrayNode();
      listWithItems.add("item1");
      listWithItems.add("item2");
      node.set("listWithItems", listWithItems);

      // Valid paths
      assertTrue(SDJsonUtils.isPathValid(node, "$.name"));
      assertTrue(SDJsonUtils.isPathValid(node, "$.address.city"));
      assertTrue(SDJsonUtils.isPathValid(node, "$.middleName"));
      assertTrue(SDJsonUtils.isPathValid(node, "$.address.*"));
      assertTrue(SDJsonUtils.isPathValid(node, "$.listWithItems[0]"));
      assertTrue(SDJsonUtils.isPathValid(node, "$.listWithItems[1]"));

      // Invalid paths
      assertFalse(SDJsonUtils.isPathValid(node, "$.invalidKey"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.address.invalidKey"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.middleName.lastName"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.emptyList[*].someField"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.emptyObj.*"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.listWithItems[01]"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.listWithItems[00]"));

      // Duplicate dot paths
      assertFalse(SDJsonUtils.isPathValid(node, "$.address..city"));
      assertFalse(SDJsonUtils.isPathValid(node, "$.address...city"));
  }

  @Test
  public void should_returnNull_when_leafNodeNameInputIsNullOrEmpty() {
      assertNull(SDJsonUtils.getLeafNodeName(null));
      assertNull(SDJsonUtils.getLeafNodeName("   "));
  }

  @Test
  public void should_returnFalse_when_pathIsNullEmptyOrMalformed() {
      ObjectNode node = JsonNodeFactory.instance.objectNode();
      node.put("name", "x");
      assertFalse(SDJsonUtils.isPathValid(node, null));
      assertFalse(SDJsonUtils.isPathValid(node, "  "));
      assertFalse(SDJsonUtils.isPathValid(node, "name.without.dollar"));
      assertTrue(SDJsonUtils.isPathValid(node, "$"));
  }

  @Test
  public void should_matchPatterns_when_anyMatchEvaluated() {
      assertFalse(SDJsonUtils.anyMatch("$.a.b", Arrays.asList("$.x.y", "$.p.q")));
      assertTrue(SDJsonUtils.anyMatch("$.a.b", Arrays.asList("$.x.y", "$.a.*")));
  }

  @Test
  public void should_discloseWholeArray_when_arrayPathIsSelectivelyDisclosable() {
      ObjectNode node = JsonNodeFactory.instance.objectNode();
      ArrayNode numbers = JsonNodeFactory.instance.arrayNode();
      numbers.add(1);
      numbers.add(2);
      node.set("nums", numbers);

      SDObjectBuilder builder = new SDObjectBuilder();
      List<Disclosure> disclosures = new ArrayList<>();
      // Mark the whole array as selectively disclosable
      SDJsonUtils.constructSDPayload(node, builder, disclosures, Arrays.asList("$.nums"), "$");

      Map<String, Object> claims = builder.build();
      // When an entire array is SD, the raw key must not remain in the digest claims
      assertFalse(claims.containsKey("nums"));
      assertFalse(disclosures.isEmpty());
  }

  @Test
  public void should_discloseNestedField_when_arrayOfObjectsHasSdPath() {
      ObjectNode node = JsonNodeFactory.instance.objectNode();
      ArrayNode people = JsonNodeFactory.instance.arrayNode();
      ObjectNode p1 = JsonNodeFactory.instance.objectNode();
      p1.put("name", "A");
      p1.put("secret", "s1");
      people.add(p1);
      node.set("people", people);

      SDObjectBuilder builder = new SDObjectBuilder();
      List<Disclosure> disclosures = new ArrayList<>();
      SDJsonUtils.constructSDPayload(node, builder, disclosures,
              Arrays.asList("$.people[0].secret"), "$");

      Map<String, Object> claims = builder.build();
      assertTrue(claims.containsKey("people"));
  }

  @Test
  public void should_listFieldsWithoutArrayIndexes_when_pathContainsFields() {
      assertEquals(Arrays.asList("address", "city"), SDJsonUtils.getPathFields("$.address.city"));
      assertEquals(Arrays.asList("nationalities"), SDJsonUtils.getPathFields("$.nationalities[*]"));
      assertEquals(Arrays.asList("people", "name"), SDJsonUtils.getPathFields("$.people[0].name"));
      assertTrue(SDJsonUtils.getPathFields("$").isEmpty());
  }

  @Test
  public void should_findPath_when_templateDeclaresItUnderTheSameParents() {
      String template = "{\"credentialSubject\": {\"address\": {\"street\": \"${street}\", \"city\": \"${city}\"}}}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.credentialSubject.address.street"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.credentialSubject.address"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.address.street"));
  }

  @Test
  public void should_notFindPath_when_sameFieldIsDeclaredUnderAnotherObject() {
      // street exists, but under office: an absent $.address.street is not an optional field.
      String template = "{\"office\": {\"street\": \"${officeStreet}\"}, \"address\": {\"city\": \"${city}\"}}";

      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.address.street"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.office.street"));
  }

  @Test
  public void should_findPath_when_fieldIsInsideAConditionalBlock() {
      String template = "{\"name\": \"${name}\" #if($nickname), \"nickname\" : \"${nickname}\"#end}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.nickname"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.nick"));
  }

  @Test
  public void should_findPath_when_fieldIsAnArrayOrInsideOne() {
      String template = "{\"nationalities\": ${nationalities}, \"people\": ["
              + "#foreach($p in $people){\"name\": \"$p.name\"}#if($foreach.hasNext),#end#end]}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.nationalities[*]"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.people[*].name"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.people[0].name"));
  }

  @Test
  public void should_ignoreValuesVelocityAndComments_when_lookingForKeys() {
      // Braces and quotes inside strings, ${...} references and comments do not change the nesting,
      // and a name used only as a value or a variable is not a declared key.
      String template = "## \"commented\": {\n"
              + "{\"note\": \"a {b} \\\"c\\\"\", \"alias\": \"${name}\", #* \"hidden\": { *# \"data\": $!{data}, \"age\": ${age}}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.age"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.data"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.name"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.commented"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.hidden"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$"));
  }

  @Test
  public void should_keepNesting_when_referenceContainsBraces() {
      // A reference ends at its matching brace, not the first one: braces nested in its arguments
      // and in its string literals must not close the object that encloses it.
      String template = "{\"address\": {\"tags\": $!{map.get(\"a}\")}, \"lines\": ${_esc.json({'k': '{'})},"
              + " \"city\": \"${city}\"}, \"zip\": ${zip}}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.address.city"));
      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.zip"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.city"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.address.zip"));
  }

  @Test
  public void should_acceptOnlyWellFormedPaths_when_checkingPathSyntax() {
      assertTrue(SDJsonUtils.isPathSyntaxValid("$.address.city"));
      assertTrue(SDJsonUtils.isPathSyntaxValid("$.nationalities[*]"));
      assertTrue(SDJsonUtils.isPathSyntaxValid("$.people[0].name"));
      assertFalse(SDJsonUtils.isPathSyntaxValid("name"));
      assertFalse(SDJsonUtils.isPathSyntaxValid("$.name[-1]"));
      assertFalse(SDJsonUtils.isPathSyntaxValid("$..name"));
      assertFalse(SDJsonUtils.isPathSyntaxValid(null));
  }

  @Test
  public void should_validatePathWithoutStackOverflow_when_pathIsVeryLong() {
      // A greedy repeated group recursed once per segment and overflowed the stack here.
      String path = "$" + ".a[0]".repeat(20_000);

      assertTrue(SDJsonUtils.isPathSyntaxValid(path));
      assertFalse(SDJsonUtils.isPathSyntaxValid(path + "[x]"));
  }

  @Test
  public void should_reportAbsent_when_dataIsMissingNullOrEmpty() throws Exception {
      JsonNode node = new ObjectMapper().readTree("{\"nickname\": null, \"nationalities\": [], \"address\": {}}");

      assertTrue(SDJsonUtils.isPathAbsent(node, "$.alias"));
      // A null part way along the path means the data is not there. A null leaf is present, as it is
      // for isPathValid, so it is disclosed and never reaches the optional-field fallback.
      assertTrue(SDJsonUtils.isPathAbsent(node, "$.nickname.first"));
      assertFalse(SDJsonUtils.isPathAbsent(node, "$.nickname"));
      assertTrue(SDJsonUtils.isPathAbsent(node, "$.nationalities[*]"));
      assertTrue(SDJsonUtils.isPathAbsent(node, "$.nationalities[0]"));
      assertTrue(SDJsonUtils.isPathAbsent(node, "$.address.*"));
      assertTrue(SDJsonUtils.isPathAbsent(node, "$.address.street"));
  }

  @Test
  public void should_reportNotAbsent_when_valueIsPresentWithAnotherShape() throws Exception {
      // Treating these as optional would issue the value as an ordinary, non-disclosable claim.
      JsonNode node = new ObjectMapper().readTree("{\"name\": \"John\", \"address\": \"12 Main St\", \"tags\": [\"a\"]}");

      assertFalse(SDJsonUtils.isPathAbsent(node, "$.name[*]"));
      assertFalse(SDJsonUtils.isPathAbsent(node, "$.address.street"));
      assertFalse(SDJsonUtils.isPathAbsent(node, "$.tags.first"));
      assertFalse(SDJsonUtils.isPathAbsent(node, "$"));
  }

  @Test
  public void should_findPath_when_objectWildcardMatchesAnyDeclaredKey() {
      String template = "{\"address\": {#if($street)\"street\": \"${street}\"#end}}";

      assertTrue(SDJsonUtils.isPathInTemplate(template, "$.address.*"));
      assertFalse(SDJsonUtils.isPathInTemplate("{\"address\": {}}", "$.address.*"));
      assertFalse(SDJsonUtils.isPathInTemplate(template, "$.office.*"));
  }
}

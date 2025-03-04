package io.mosip.certify.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
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

import junit.framework.TestCase;

public class SDJsonUtilsTest extends TestCase {

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
      path1 = "$.store.book[0].*";
      path2 = "$.store.book[0].author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.*.author";
      path2 = "$.store.book.author";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[0].author";
      assertFalse(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$";
      path2 = "$";
      assertTrue(SDJsonUtils.compareJsonPaths(path1, path2));
      path1 = "$.store.book[*].author";
      path2 = "$.store.book[0].author";
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
     // List<String> sdPaths = Arrays.asList("$.age","$.address.street", "$.phoneNumbers", "$.address.geo.latitude");
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
                .type(new JOSEObjectType("vc+sd-jwt")).build();
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
     // assertTrue(sdObjectBuilder.containsClaim("address"));
     // assertTrue(sdObjectBuilder.containsClaim("street"));
     // assertTrue(sdObjectBuilder.containsClaim("city"));

      // Check claims for phoneNumbers array
     // assertTrue(sdObjectBuilder.containsClaim("phoneNumbers"));
     // assertTrue(sdObjectBuilder.containsClaim("type"));
     // assertTrue(sdObjectBuilder.containsClaim("number"));
    }

}
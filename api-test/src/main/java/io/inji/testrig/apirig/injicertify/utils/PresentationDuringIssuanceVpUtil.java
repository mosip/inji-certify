package io.inji.testrig.apirig.injicertify.utils;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;

/**
 * Builds {@code openid4vp_response} for Presentation During Issuance using the
 * same VP signing flow as Mimoto {@code WalletPresentationServiceImpl} /
 * inji-openid4vp {@code UnsignedLdpVPTokenBuilder}.
 */
public final class PresentationDuringIssuanceVpUtil {

	private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceVpUtil.class);
	private static final ObjectMapper objectMapper = new ObjectMapper();
	private static final String SIGNATURE_SUITE = "JsonWebSignature2020";

	private PresentationDuringIssuanceVpUtil() {
	}

	public static JSONObject buildOpenId4VpResponse(JSONObject openId4VpRequest) {
		try {
			JSONObject holderJwk = InjiCertifyUtil.getPresentationDuringIssuanceVpTestData("holderJwk");
			OctetKeyPair holderKey = OctetKeyPair.parse(holderJwk.toString());
			String holderDid = toDidJwk(holderKey);
			JSONObject vc = InjiCertifyUtil.getPresentationDuringIssuanceVpTestData("sampleMosipIdentityVc");

			String nonce = openId4VpRequest.getString("nonce");
			String domain = openId4VpRequest.getString("client_id");
			String created = formatCreatedDate(new Date());

			JSONObject vpToken = new JSONObject();
			vpToken.put("@context", new JSONArray().put("https://www.w3.org/2018/credentials/v1")
					.put("https://w3id.org/security/suites/jws-2020/v1"));
			vpToken.put("type", new JSONArray().put("VerifiablePresentation"));
			vpToken.put("id", UUID.randomUUID().toString());
			vpToken.put("holder", holderDid);
			vpToken.put("verifiableCredential", new JSONArray().put(vc));

			JSONObject proof = new JSONObject();
			proof.put("type", SIGNATURE_SUITE);
			proof.put("created", created);
			proof.put("challenge", nonce);
			proof.put("domain", domain);
			proof.put("proofPurpose", "authentication");
			proof.put("verificationMethod", holderDid);
			vpToken.put("proof", proof);

			String dataToSign = canonicalizeVpToken(vpToken);
			String jws = signDetachedJwt(holderKey, dataToSign);
			proof.put("jws", jws);

			JSONObject presentationSubmission = buildPresentationSubmission(
					openId4VpRequest.getJSONObject("presentation_definition"));

			JSONObject response = new JSONObject();
			response.put("vp_token", vpToken);
			response.put("presentation_submission", presentationSubmission);
			return response;
		} catch (Exception e) {
			logger.error("Failed to build openid4vp_response: " + e.getMessage(), e);
			throw new RuntimeException("Failed to build openid4vp_response", e);
		}
	}

	private static String canonicalizeVpToken(JSONObject vpToken) throws Exception {
		Map<String, Object> vpMap = objectMapper.readValue(vpToken.toString(),
				new TypeReference<Map<String, Object>>() {
				});

		JsonLDObject vpLd = JsonLDObject.fromJsonObject(vpMap);
		ConfigurableDocumentLoader documentLoader = new ConfigurableDocumentLoader();
		documentLoader.setEnableHttps(true);
		documentLoader.setEnableHttp(true);
		documentLoader.setEnableFile(false);
		vpLd.setDocumentLoader(documentLoader);

		LdProof ldProof = LdProof.getFromJsonLDObject(vpLd);
		byte[] canonicalBytes = new URDNA2015Canonicalizer().canonicalize(ldProof, vpLd);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(canonicalBytes);
	}

	private static String signDetachedJwt(OctetKeyPair holderKey, String dataToSignBase64Url) throws Exception {
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA).base64URLEncodePayload(false)
				.criticalParams(Set.of("b64")).build();
		String headerJson = header.toString();
		String header64 = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
		byte[] payloadBytes = Base64.getUrlDecoder().decode(dataToSignBase64Url);

		byte[] headerBytes = header64.getBytes(StandardCharsets.UTF_8);
		byte[] signingInput = new byte[headerBytes.length + 1 + payloadBytes.length];
		System.arraycopy(headerBytes, 0, signingInput, 0, headerBytes.length);
		signingInput[headerBytes.length] = '.';
		System.arraycopy(payloadBytes, 0, signingInput, headerBytes.length + 1, payloadBytes.length);

		Base64URL signature = new Ed25519Signer(holderKey).sign(header, signingInput);
		return header64 + ".." + signature;
	}

	private static JSONObject buildPresentationSubmission(JSONObject presentationDefinition) {
		JSONObject presentationSubmission = new JSONObject();
		presentationSubmission.put("id", "urn:uuid:" + UUID.randomUUID());
		presentationSubmission.put("definition_id", presentationDefinition.getString("id"));

		JSONArray descriptorMap = new JSONArray();
		JSONArray inputDescriptors = presentationDefinition.getJSONArray("input_descriptors");
		for (int i = 0; i < inputDescriptors.length(); i++) {
			String descriptorId = inputDescriptors.getJSONObject(i).getString("id");
			JSONObject descriptor = new JSONObject();
			descriptor.put("id", descriptorId);
			descriptor.put("format", "ldp_vp");
			descriptor.put("path", "$");
			JSONObject pathNested = new JSONObject();
			pathNested.put("id", descriptorId);
			pathNested.put("format", "ldp_vc");
			pathNested.put("path", "$.verifiableCredential[" + i + "]");
			descriptor.put("path_nested", pathNested);
			descriptorMap.put(descriptor);
		}
		presentationSubmission.put("descriptor_map", descriptorMap);
		return presentationSubmission;
	}

	private static String formatCreatedDate(Date created) {
		return new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).format(created);
	}

	static String toDidJwk(OctetKeyPair holderKey) {
		String publicJwkJson = holderKey.toPublicJWK().toJSONString();
		String encoded = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(publicJwkJson.getBytes(StandardCharsets.UTF_8));
		return "did:jwk:" + encoded + "#0";
	}

}

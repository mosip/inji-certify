package io.inji.testrig.apirig.injicertify.utils;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.SkipException;

import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

/**
 * Builds the DCQL {@code openid4vp_response} for Presentation During Issuance using
 * the same VP signing flow as Mimoto {@code WalletPresentationServiceImpl} /
 * inji-openid4vp {@code UnsignedLdpVPTokenBuilder}.
 */
public final class PresentationDuringIssuanceVpUtil {

	private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceVpUtil.class);
	private static final ObjectMapper objectMapper = new ObjectMapper();
	private static final String SIGNATURE_SUITE = "JsonWebSignature2020";
	private static final ConfigurableDocumentLoader PRESENTATION_DOCUMENT_LOADER = presentationDocumentLoader();

	/**
	 * Fixed Ed25519 holder. verify-core only verifies JsonWebSignature2020 with EdDSA,
	 * so both the MOSIP VC ({@code $PROOF_JWT_PDI_HOLDER$}) and the IAR VP must use
	 * this key. Kept as JSON rather than loaded from the GetCredential hbs so VP
	 * signing does not depend on the test-rig resource path.
	 */
	static final String PDI_HOLDER_JWK_JSON =
			"{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"Xpge_SRooikfFoE9n6VhBwBEMFwJIGtIX_W_hH8UTg0\","
					+ "\"d\":\"hdYM0kK-bfd4GKCna8Aqf0oChMwdeXu5Ik63h6xaUVU\",\"use\":\"sig\"}";

	private PresentationDuringIssuanceVpUtil() {
	}

	public static JSONObject buildOpenId4VpResponse(JSONObject openId4VpRequest) {
		try {
			JWK holderKey = resolvePresentationHolderJwk();
			JSONObject vc = InjiCertifyUtil.getPresentationDuringIssuanceVpTestData("sampleMosipIdentityVc");
			String holderDid = holderDidForPresentedVc(holderKey, vc);
			String verificationMethod = didJwkVerificationMethod(holderDid);

			String nonce = openId4VpRequest.getString("nonce");
			String domain = openId4VpRequest.getString("client_id");
			String created = formatCreatedDate(new Date());

			JSONObject presentation = new JSONObject();
			presentation.put("@context", new JSONArray().put("https://www.w3.org/2018/credentials/v1")
					.put("https://w3id.org/security/suites/jws-2020/v1"));
			presentation.put("type", new JSONArray().put("VerifiablePresentation"));
			presentation.put("id", "urn:uuid:" + UUID.randomUUID());
			presentation.put("holder", holderDid);
			presentation.put("verifiableCredential", new JSONArray().put(vc));

			JSONObject proof = new JSONObject();
			proof.put("type", SIGNATURE_SUITE);
			proof.put("created", created);
			proof.put("challenge", nonce);
			proof.put("domain", domain);
			proof.put("proofPurpose", "authentication");
			proof.put("verificationMethod", verificationMethod);
			presentation.put("proof", proof);

			String dataToSign = canonicalizePresentation(presentation);
			String jws = signDetachedJwt(holderKey, dataToSign);
			proof.put("jws", jws);

			JSONObject response = new JSONObject();
			response.put("vp_token", buildDcqlVpToken(resolveDcqlQueryId(openId4VpRequest), presentation));
			return response;
		} catch (SkipException e) {
			throw e;
		} catch (Exception e) {
			logger.error("Failed to build openid4vp_response: " + e.getMessage(), e);
			throw new RuntimeException("Failed to build openid4vp_response", e);
		}
	}

	/**
	 * verify-core {@code PresentationVerifier} accepts only EdDSA for
	 * {@code JsonWebSignature2020}. Signing with the MOSIP ID OIDC RSA JWK produces
	 * {@code alg=RS256} and the server answers {@code Unsupported JWS algorithm}.
	 * The MOSIP VC must be bound to this same key via {@code $PROOF_JWT_PDI_HOLDER$}.
	 */
	static JWK resolvePresentationHolderJwk() throws Exception {
		logger.info("Signing Presentation During Issuance VP with Ed25519 holder JWK");
		return pdiHolderOctetKeyPair();
	}

	public static OctetKeyPair pdiHolderOctetKeyPair() throws Exception {
		return OctetKeyPair.parse(PDI_HOLDER_JWK_JSON);
	}

	private static String canonicalizePresentation(JSONObject presentation) throws Exception {
		Map<String, Object> vpMap = objectMapper.readValue(presentation.toString(),
				new TypeReference<Map<String, Object>>() {
				});

		JsonLDObject vpLd = JsonLDObject.fromJsonObject(vpMap);
		vpLd.setDocumentLoader(PRESENTATION_DOCUMENT_LOADER);

		LdProof ldProof = LdProof.getFromJsonLDObject(vpLd);
		byte[] canonicalBytes = new URDNA2015Canonicalizer().canonicalize(ldProof, vpLd);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(canonicalBytes);
	}

	/**
	 * The VP and the embedded MOSIP VC name these contexts by URL. Serving the
	 * published documents from the classpath keeps canonicalization working when
	 * the runner cannot reach w3.org, w3id.org, or github.io.
	 */
	private static ConfigurableDocumentLoader presentationDocumentLoader() {
		try {
			ConfigurableDocumentLoader loader = new ConfigurableDocumentLoader();
			loader.setEnableHttps(true);
			loader.setEnableHttp(true);
			loader.setEnableFile(false);
			loader.getLocalCache().putAll(LDSecurityContexts.CONTEXTS);
			cacheClasspathContext(loader, "https://www.w3.org/2018/credentials/v1", "jsonld/credentials-v1.jsonld");
			cacheClasspathContext(loader, "https://inji.github.io/inji-config/contexts/mosip-identity-context.json",
					"jsonld/mosip-identity-context.json");
			return loader;
		} catch (Exception e) {
			throw new ExceptionInInitializerError(e);
		}
	}

	private static void cacheClasspathContext(ConfigurableDocumentLoader loader, String url, String resource)
			throws Exception {
		try (InputStream in = PresentationDuringIssuanceVpUtil.class.getClassLoader().getResourceAsStream(resource)) {
			if (in == null) {
				throw new IllegalStateException("Missing JSON-LD context " + resource);
			}
			JsonDocument document = JsonDocument.of(MediaType.JSON_LD, in);
			document.setDocumentUrl(URI.create(url));
			loader.getLocalCache().put(URI.create(url), document);
		}
	}

	static String signDetachedJwt(JWK holderKey, String dataToSignBase64Url) throws Exception {
		if (!(holderKey instanceof OctetKeyPair octetKeyPair)) {
			throw new IllegalArgumentException("Unsupported holder JWK type: " + holderKey.getKeyType());
		}
		JWSSigner signer = new Ed25519Signer(octetKeyPair);
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

		Base64URL signature = signer.sign(header, signingInput);
		return header64 + ".." + signature;
	}

	/**
	 * DCQL keys each presentation by the credential query it answers, and verify-core
	 * throws {@code InvalidVpTokenException} for any value that is not an array. There
	 * is no {@code presentation_submission}: that belongs to Presentation Exchange, and
	 * Certify does not read it in DCQL mode.
	 */
	static JSONObject buildDcqlVpToken(String queryId, JSONObject presentation) {
		return new JSONObject().put(queryId, new JSONArray().put(presentation));
	}

	/**
	 * A single MOSIP identity VC is presented, so the {@code ldp_vc} query is the one
	 * it can satisfy.
	 */
	static String resolveDcqlQueryId(JSONObject openId4VpRequest) {
		JSONObject dcqlQuery = openId4VpRequest.optJSONObject("dcql_query");
		if (dcqlQuery == null) {
			throw new IllegalArgumentException(
					"openid4vp_request carries no dcql_query; Certify sends DCQL for Presentation During Issuance");
		}
		JSONArray credentials = dcqlQuery.optJSONArray("credentials");
		if (credentials == null || credentials.length() == 0) {
			throw new IllegalArgumentException("dcql_query.credentials is empty, so nothing can key the vp_token");
		}
		for (int i = 0; i < credentials.length(); i++) {
			JSONObject credential = credentials.getJSONObject(i);
			if ("ldp_vc".equals(credential.optString("format"))) {
				return credential.getString("id");
			}
		}
		return credentials.getJSONObject(0).getString("id");
	}

	private static String formatCreatedDate(Date created) {
		return formatCreatedDateUtc(created.toInstant());
	}

	static String formatCreatedDateUtc(Instant instant) {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US);
		formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
		return formatter.format(Date.from(instant));
	}

	static String holderDidForPresentedVc(JWK holderKey, JSONObject vc) {
		JSONObject credentialSubject = vc == null ? null : vc.optJSONObject("credentialSubject");
		String subjectId = credentialSubject == null ? "" : credentialSubject.optString("id", "");
		if (subjectId.startsWith("did:jwk:")) {
			return normalizeHolderDidForVp(subjectId);
		}
		return normalizeHolderDidForVp(toDidJwk(holderKey));
	}

	static String holderDidForPresentedVc(OctetKeyPair holderKey, JSONObject vc) {
		return holderDidForPresentedVc((JWK) holderKey, vc);
	}

	static String didJwkVerificationMethod(String did) {
		return normalizeHolderDidForVp(did);
	}

	public static String canonicalDidJwkForHolder(OctetKeyPair holderKey) {
		return canonicalDidJwkForHolder((JWK) holderKey);
	}

	public static String canonicalDidJwkForHolder(JWK holderKey) {
		return normalizeHolderDidForVp(toDidJwk(holderKey));
	}

	static String toDidJwk(JWK holderKey) {
		String publicJwkJson = holderKey.toPublicJWK().toJSONString();
		String encoded = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(publicJwkJson.getBytes(StandardCharsets.UTF_8));
		return "did:jwk:" + encoded;
	}

	static String toDidJwk(OctetKeyPair holderKey) {
		return toDidJwk((JWK) holderKey);
	}

	static String toDidJwkPadded(OctetKeyPair holderKey) {
		String publicJwkJson = holderKey.toPublicJWK().toJSONString();
		return "did:jwk:" + Base64.getUrlEncoder().encodeToString(publicJwkJson.getBytes(StandardCharsets.UTF_8));
	}

	static String ensureDidJwkBase64Unpadded(String did) {
		if (did == null || !did.startsWith("did:jwk:")) {
			return did;
		}
		String encoded = did.substring("did:jwk:".length());
		int fragmentIndex = encoded.indexOf('#');
		if (fragmentIndex >= 0) {
			encoded = encoded.substring(0, fragmentIndex);
		}
		while (encoded.endsWith("=")) {
			encoded = encoded.substring(0, encoded.length() - 1);
		}
		return "did:jwk:" + encoded;
	}

	static String normalizeHolderDidForVp(String did) {
		return ensureDidJwkBase64Unpadded(did) + "#0";
	}

}

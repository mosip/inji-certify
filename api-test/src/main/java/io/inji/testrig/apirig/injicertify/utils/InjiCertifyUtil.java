package io.inji.testrig.apirig.injicertify.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringWriter;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.regex.Pattern;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bitcoinj.base.Base58;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.testng.SkipException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.javafaker.Faker;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import io.inji.testrig.apirig.injicertify.testrunner.InjiTestRunner;
import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.CryptoCoreUtil;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.JWKKeyUtil;
import io.mosip.testrig.apirig.utils.KeyMgrUtility;
import io.mosip.testrig.apirig.utils.NotificationListener;
import io.mosip.testrig.apirig.utils.RestClient;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;
import io.restassured.response.Response;

public class InjiCertifyUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(InjiCertifyUtil.class);
	public static String currentUseCase = "";
	private static Faker faker = new Faker();
	private static String fullNameForSunBirdR = generateFullNameForSunBirdR();
	private static String dobForSunBirdR = generateDobForSunBirdR();
	private static String policyNumberForSunBirdR = generateRandomNumberString(9);
	private static final ObjectMapper mapper = new ObjectMapper();
	
public static List<String> testCasesInRunScope = new ArrayList<>();

	private static final String SAMPLE_MOSIP_IDENTITY_VC_CACHE_KEY = "PresentationDuringIssuance_sampleMosipIdentityVc";
	private static final String MOSIP_ID_PARTNER_ID_KEYWORD =
			"$ID:PartnerSelfRegistration_MOSIPID_All_Valid_Smoke_sid_partnerId$";
	/** Mock eSignet partner. Valid for mdl/mdocvp mock OIDC, not for released IDA. */
	private static final String MOCK_ESIGNET_RELYING_PARTY_ID = "Bharathi-Inc";
	/**
	 * Default IDA auth partner on a standard MOSIP stack. eSignet passes
	 * relyingPartyId to IDA on send-otp; IDA-MLC-007 is the generic failure when
	 * that partner is unknown (for example Bharathi-Inc).
	 */
	private static final String DEFAULT_MOSIP_ID_ESIGNET_RELYING_PARTY_ID = "mpartner-default-mobile";
	private static final Set<String> MDOCVP_MOSIP_ID_VCI_PREREQUISITE_IDS = Collections.unmodifiableSet(new HashSet<>(
			Arrays.asList("TC_idrepo_dependency_01", "TC_pms_dependency_01", "TC_pms_dependency_02",
					"TC_pms_dependency_03", "TC_pms_dependency_04", "TC_pms_dependency_05", "TC_pms_dependency_06",
					"TC_pms_dependency_07", "TC_pms_dependency_08", "TC_pms_dependency_09", "TC_pms_dependency_10",
					"TC_InjiCertify_MosipID_AddCredentialConfig_01", "TC_esignetDependent_OAuthdetailsRequestNeg_26",
					"TC_esignetDependent_AuthenticateUser_26", "TC_esignetDependent_AuthorizationCode_27",
					"TC_esignetDependent_GenerateToken_27", "TC_esignetDependent_GenerateNonce_01",
					"TC_injicertify_Mosipidcredentialissuance_pdi_01")));

private static String trimLowerUseCase() {
	if (currentUseCase == null || currentUseCase.isBlank()) {
		return "";
	}
	return currentUseCase.trim().toLowerCase(Locale.ROOT);
}

public static void setLogLevel() {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}
	
public static void configureOtp() {
	// For mock, mdoc and landregistry usecase also the OTP value is hard coded and not configurable.

	String cu = currentUseCase != null ? currentUseCase.trim() : "";
	if (!cu.isEmpty() && (cu.equals("mock") || cu.equals("landregistry") || cu.equals("mdl")
			|| cu.equals("mdocvp"))) {

		Map<String, Object> additionalPropertiesMap = new HashMap<>();
			additionalPropertiesMap.put(InjiCertifyConstants.USE_PRE_CONFIGURED_OTP_STRING,
					InjiCertifyConstants.TRUE_STRING);
			additionalPropertiesMap.put(InjiCertifyConstants.PRE_CONFIGURED_OTP_STRING,
					InjiCertifyConstants.ALL_ONE_OTP_STRING);
			InjiCertifyConfigManager.add(additionalPropertiesMap);
		}
		// else do nothing
	}

	public static String extractAndEncodeVcTemplate(String requestJsonStr) {
		JSONObject requestJson = new JSONObject(requestJsonStr);
		Object vcTemplateObj = requestJson.opt("vcTemplate");
		if (vcTemplateObj == null) {
			return requestJsonStr;
		}

		final String vcTemplateStr;
		if (vcTemplateObj instanceof JSONObject) {
			vcTemplateStr = unwrapRawPlaceholders(((JSONObject) vcTemplateObj).toString());
		} else if (vcTemplateObj instanceof String) {
			// Velocity templates contain directives (#set/#if) and are not JSON; they are stored as raw strings.
			vcTemplateStr = unwrapRawPlaceholders((String) vcTemplateObj);
		} else {
			vcTemplateStr = unwrapRawPlaceholders(String.valueOf(vcTemplateObj));
		}

		return requestJson.put("vcTemplate", AdminTestUtil.encodeBase64(vcTemplateStr)).toString();
	}
	public static void dBCleanup() {
		DBManager.executeDBQueries(InjiCertifyConfigManager.getKMDbUrl(), InjiCertifyConfigManager.getKMDbUser(),
				InjiCertifyConfigManager.getKMDbPass(), InjiCertifyConfigManager.getKMDbSchema(),
				getGlobalResourcePath() + "/" + "config/keyManagerCertDataDeleteQueries.txt");
		
		DBManager.executeDBQueries(InjiCertifyConfigManager.getIdaDbUrl(), InjiCertifyConfigManager.getIdaDbUser(),
				InjiCertifyConfigManager.getPMSDbPass(), InjiCertifyConfigManager.getIdaDbSchema(),
				getGlobalResourcePath() + "/" + "config/idaCertDataDeleteQueries.txt");
		
		DBManager.executeDBQueries(InjiCertifyConfigManager.getMASTERDbUrl(),
				InjiCertifyConfigManager.getMasterDbUser(), InjiCertifyConfigManager.getMasterDbPass(),
				InjiCertifyConfigManager.getMasterDbSchema(),
				getGlobalResourcePath() + "/" + "config/masterDataCertDataDeleteQueries.txt");
		
		DBManager.executeDBQueries(InjiCertifyConfigManager.getPMSDbUrl(), InjiCertifyConfigManager.getPMSDbUser(),
				InjiCertifyConfigManager.getPMSDbPass(), InjiCertifyConfigManager.getPMSDbSchema(),
				getGlobalResourcePath() + "/" + "config/pmsDataDeleteQueries.txt");
		
	}
	
	public static void landRegistryDBCleanup() {

		DBManager.executeDBQueries(InjiCertifyConfigManager.getInjiCertifyDBURL(),
				InjiCertifyConfigManager.getproperty("db-su-user"),
				InjiCertifyConfigManager.getproperty("postgres-password"),
				InjiCertifyConfigManager.getproperty("inji_certify_schema"),
				getGlobalResourcePath() + "/" + "config/landRegistryDataDeleteQueries.txt");

	}

	public static String smtpOtpHandler(String inputJson, TestCaseDTO testCaseDTO) {
		boolean restorePreconfiguredOtp = false;
		String previousPreconfiguredOtp = null;
		if (isMosipIdOtpTest(testCaseDTO)
				&& InjiCertifyConstants.TRUE_STRING
						.equalsIgnoreCase(InjiCertifyConfigManager.getUsePreConfiguredOtp())) {
			previousPreconfiguredOtp = InjiCertifyConfigManager.getUsePreConfiguredOtp();
			Map<String, Object> mosipIdOtpProperties = new HashMap<>();
			mosipIdOtpProperties.put(InjiCertifyConstants.USE_PRE_CONFIGURED_OTP_STRING, "false");
			InjiCertifyConfigManager.add(mosipIdOtpProperties);
			restorePreconfiguredOtp = true;
			logger.info("Using email OTP for Mosip ID authenticate; preconfigured OTP is ignored");
		}
		try {
			return replaceChallengeWithEmailOtp(inputJson);
		} finally {
			if (restorePreconfiguredOtp) {
				Map<String, Object> restore = new HashMap<>();
				restore.put(InjiCertifyConstants.USE_PRE_CONFIGURED_OTP_STRING, previousPreconfiguredOtp);
				InjiCertifyConfigManager.add(restore);
			}
		}
	}

	private static boolean isMosipIdOtpTest(TestCaseDTO testCaseDTO) {
		return testCaseDTO != null && isMosipIdTestName(testCaseDTO.getTestCaseName());
	}

	private static boolean isMdocvpUseCase() {
		return "mdocvp".equals(trimLowerUseCase());
	}

	/**
	 * First row of inji-config {@code driving_license_mosipid.csv} (dev-int).
	 * MockCSVDataProviderPlugin looks up the IAR token {@code sub} against that
	 * column. AddIdentity still uses a fresh idgenerator UIN so IDA can send OTP;
	 * after IAR-with-VP succeeds we rewrite {@code iar_session.identity_data} to
	 * this id so the subsequent token {@code sub} matches the CSV.
	 */
	public static final String DEFAULT_MDOCVP_CSV_IDENTITY_ID = "6039071423";
	public static final String MDOCVP_IAR_VP_SMOKE_UNIQUE_ID = "TC_InjiCertify_IARInitialRequest_With_VP_01";
	private static final Pattern SAFE_IAR_SESSION_TOKEN = Pattern.compile("[A-Za-z0-9._:-]+");

	public static String mdocvpCsvIdentityId() {
		try {
			String configured = InjiCertifyConfigManager.getproperty("mdocvpCsvIdentityId");
			if (configured != null && !configured.isBlank() && !"null".equalsIgnoreCase(configured.trim())) {
				return configured.trim();
			}
		} catch (RuntimeException ignored) {
			// Unit tests may call this before ConfigManager.init().
		}
		return DEFAULT_MDOCVP_CSV_IDENTITY_ID;
	}

	public static boolean shouldRewriteMdocvpIarSessionIdentity(TestCaseDTO testCaseDTO) {
		if (!isMdocvpUseCase() || testCaseDTO == null) {
			return false;
		}
		String uniqueIdentifier = testCaseDTO.getUniqueIdentifier();
		return uniqueIdentifier != null && MDOCVP_IAR_VP_SMOKE_UNIQUE_ID.equals(uniqueIdentifier.trim());
	}

	public static String mdocvpIarSessionIdentityUpdateSql(String authSession, String csvIdentityId)
			throws AdminTestException {
		if (!isSafeIarSessionToken(authSession) || !isSafeIarSessionToken(csvIdentityId)) {
			throw new AdminTestException(
					"Refusing IAR session identity rewrite: auth_session or CSV id is not a safe token");
		}
		return "UPDATE iar_session SET identity_data = '" + csvIdentityId + "' WHERE auth_session = '"
				+ authSession + "'";
	}

	static boolean isSafeIarSessionToken(String value) {
		return value != null && !value.isBlank() && SAFE_IAR_SESSION_TOKEN.matcher(value.trim()).matches();
	}

	public static void rewriteMdocvpIarSessionIdentityToCsvId(TestCaseDTO testCaseDTO, String requestJson)
			throws AdminTestException {
		if (!shouldRewriteMdocvpIarSessionIdentity(testCaseDTO)) {
			return;
		}
		if (requestJson == null || requestJson.isBlank()) {
			throw new AdminTestException("IAR VP request body is missing; cannot rewrite iar_session.identity_data");
		}
		String authSession;
		try {
			authSession = new JSONObject(requestJson).optString("auth_session", "").trim();
		} catch (JSONException e) {
			throw new AdminTestException("IAR VP request is not JSON; cannot rewrite iar_session.identity_data");
		}
		String csvIdentityId = mdocvpCsvIdentityId();
		String sql = mdocvpIarSessionIdentityUpdateSql(authSession, csvIdentityId);
		String selectSql = "SELECT auth_session FROM iar_session WHERE auth_session = '" + authSession + "'";
		logger.error("Rewriting mdocvp IAR session identity_data to the configured CSV identity");
		try {
			String dbUrl = resolveInjiCertifyJdbcUrl();
			String dbUser = InjiCertifyConfigManager.getproperty("db-su-user");
			String dbPass = InjiCertifyConfigManager.getproperty("postgres-password");
			String dbSchema = InjiCertifyConfigManager.getproperty("inji_certify_schema");
			List<Map<String, Object>> rows = ExtendedDBManager.executeSelectQuery(dbUrl, dbUser, dbPass, dbSchema,
					selectSql);
			if (rows == null || rows.isEmpty()) {
				throw new AdminTestException(
						"iar_session not found for the IAR auth_session. Check mdocvpCertifyDbName.");
			}
			ExtendedDBManager.executeDBWithQueries(dbUrl, dbUser, dbPass, dbSchema, sql);
		} catch (AdminTestException e) {
			throw e;
		} catch (Exception e) {
			throw new AdminTestException(
					"Failed to rewrite iar_session.identity_data to the CSV identity so GetCredential "
							+ "can look up driving_license_mosipid.csv: " + e.getMessage());
		}
	}

	static String resolveInjiCertifyJdbcUrl() {
		if (isMdocvpUseCase()) {
			String mdocDb = null;
			try {
				mdocDb = InjiCertifyConfigManager.getproperty("mdocvpCertifyDbName");
			} catch (RuntimeException ignored) {
				// Unit tests may call this before ConfigManager.init().
			}
			if (mdocDb != null && !mdocDb.isBlank() && !"null".equalsIgnoreCase(mdocDb.trim())) {
				return "jdbc:postgresql://" + InjiCertifyConfigManager.getproperty("db-server") + ":"
						+ InjiCertifyConfigManager.getproperty("db-port") + "/" + mdocDb.trim();
			}
		}
		return InjiCertifyConfigManager.getInjiCertifyDBURL();
	}

	public static final String MDOCVP_DRIVING_LICENSE_CONFIG_KEY = "DrivingLicenseCredential";
	private static boolean mdocDrivingLicenseSignedEnsured;

	public static boolean shouldEnsureMdocValiditySigned(TestCaseDTO testCaseDTO) {
		if (!isMdocvpUseCase() || testCaseDTO == null || testCaseDTO.getUniqueIdentifier() == null) {
			return false;
		}
		return "TC_InjiCertify_GetCredentialFormDocvp_01".equals(testCaseDTO.getUniqueIdentifier().trim());
	}

	/**
	 * Seeded mDoc templates are Velocity, not JSON ({@code ${drivingPrivileges}} is
	 * unquoted). Do not parse them with {@link JSONObject}.
	 */
	public static String addSignedPlaceholderToMdocVcTemplate(String vcTemplate) {
		if (vcTemplate == null || vcTemplate.isBlank()) {
			return vcTemplate;
		}
		String decoded = decodePossiblyBase64Json(vcTemplate);
		if (decoded.contains("\"signed\":")) {
			return decoded;
		}
		java.util.regex.Matcher validUntil = Pattern
				.compile("(\"validUntil\"\\s*:\\s*\"\\$\\{_validUntil}\")").matcher(decoded);
		if (!validUntil.find()) {
			return decoded;
		}
		return decoded.substring(0, validUntil.end()) + ",\n    \"signed\": \"${_signed}\""
				+ decoded.substring(validUntil.end());
	}

	static String decodePossiblyBase64Json(String value) {
		String trimmed = value.trim();
		if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
			return trimmed;
		}
		try {
			String decoded = new String(Base64.getDecoder().decode(trimmed), StandardCharsets.UTF_8).trim();
			if (decoded.startsWith("{") || decoded.startsWith("[")) {
				return decoded;
			}
		} catch (IllegalArgumentException ignored) {
			// Not base64; treat as raw JSON below.
		}
		return trimmed;
	}

	public static void ensureMdocDrivingLicenseTemplateHasSigned(TestCaseDTO testCaseDTO) {
		if (!shouldEnsureMdocValiditySigned(testCaseDTO) || mdocDrivingLicenseSignedEnsured) {
			return;
		}
		String certifyBase = InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		if (certifyBase == null || certifyBase.isBlank()) {
			return;
		}
		String url = certifyBase.replaceAll("/+$", "") + "/v1/certify/credential-configurations/"
				+ MDOCVP_DRIVING_LICENSE_CONFIG_KEY;
		try {
			Response existing = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
			if (existing == null || existing.getStatusCode() != 200) {
				logger.error("Could not load " + MDOCVP_DRIVING_LICENSE_CONFIG_KEY
						+ " to add validityInfo.signed; HTTP "
						+ (existing == null ? "null" : existing.getStatusCode()));
				return;
			}
			JSONObject config = new JSONObject(existing.asString());
			String original = config.optString("vcTemplate", "");
			String updated = addSignedPlaceholderToMdocVcTemplate(original);
			if (updated == null || updated.equals(decodePossiblyBase64Json(original))) {
				mdocDrivingLicenseSignedEnsured = updated != null && updated.contains("\"signed\":");
				return;
			}
			// Stored templates are Base64; VelocityTemplatingEngineImpl decodes them.
			config.put("vcTemplate", AdminTestUtil.encodeBase64(updated));
			logger.error("Updating " + MDOCVP_DRIVING_LICENSE_CONFIG_KEY
					+ " vcTemplate to include validityInfo.signed=${_signed}");
			Response put = io.restassured.RestAssured.given().relaxedHTTPSValidation()
					.contentType("application/json").body(config.toString()).put(url);
			if (put == null || put.getStatusCode() >= 300) {
				logger.error("Failed to patch " + MDOCVP_DRIVING_LICENSE_CONFIG_KEY
						+ " with signed validityInfo: HTTP "
						+ (put == null ? "null" : put.getStatusCode()) + " "
						+ (put == null ? "" : put.asString()));
				return;
			}
			mdocDrivingLicenseSignedEnsured = true;
		} catch (Exception e) {
			logger.error("Could not add validityInfo.signed to " + MDOCVP_DRIVING_LICENSE_CONFIG_KEY
					+ "; GetCredential will use the seeded template. " + e.getMessage());
		}
	}

	/**
	 * Relying party eSignet sends to IDA for MOSIP ID OTP/KYC. Configurable via
	 * mosipIdEsignetRelyingPartyId; defaults to mpartner-default-mobile.
	 */
	static String mosipIdEsignetRelyingPartyId() {
		try {
			String configured = InjiCertifyConfigManager.getproperty("mosipIdEsignetRelyingPartyId");
			if (configured != null && !configured.isBlank() && !"null".equalsIgnoreCase(configured.trim())) {
				return configured.trim();
			}
		} catch (RuntimeException ignored) {
			// Unit tests may call this before ConfigManager.init().
		}
		return DEFAULT_MOSIP_ID_ESIGNET_RELYING_PARTY_ID;
	}

	static boolean isMosipIdTestName(String testCaseName) {
		return testCaseName != null && testCaseName.toUpperCase(Locale.ROOT).contains("MOSIPID");
	}

	/**
	 * Released IDA returns IDA-MLC-018 while a newly created UIN is still being
	 * indexed. This MOSIP ID stack often wraps the same window as IDA-MLC-007 or
	 * eSignet {@code send_otp_failed} without the IDA code on later attempts.
	 */
	public static boolean isRetryableMosipIdSendOtpFailure(Response otpResponse) {
		if (otpResponse == null) {
			return false;
		}
		try {
			return isRetryableMosipIdSendOtpFailure(otpResponse.asString());
		} catch (Exception e) {
			logger.warn("Could not read send-otp body: " + e.getMessage());
			return false;
		}
	}

	static boolean isRetryableMosipIdSendOtpFailure(String body) {
		if (body == null || body.isBlank()) {
			return false;
		}
		return body.contains("IDA-MLC-018") || body.contains("IDA-MLC-007") || body.contains("send_otp_failed");
	}

	public static String describeMosipIdSendOtpFailure(Response otpResponse) {
		if (otpResponse == null) {
			return "empty send-otp response";
		}
		try {
			return describeMosipIdSendOtpFailure(otpResponse.asString());
		} catch (Exception e) {
			return "unreadable send-otp response";
		}
	}

	static String describeMosipIdSendOtpFailure(String body) {
		if (body == null) {
			return "empty send-otp response";
		}
		if (body.contains("IDA-MLC-018")) {
			return "IDA-MLC-018";
		}
		if (body.contains("IDA-MLC-007")) {
			return "IDA-MLC-007";
		}
		if (body.contains("send_otp_failed")) {
			return "send_otp_failed";
		}
		return "unknown send-otp error";
	}

	private static String firstNonBlank(String... values) {
		if (values == null) {
			return null;
		}
		for (String value : values) {
			if (value != null && !value.isBlank()) {
				return value.trim();
			}
		}
		return null;
	}

	public static int parsePositiveInt(String raw, int defaultValue) {
		if (raw == null || raw.isBlank()) {
			return defaultValue;
		}
		try {
			int parsed = Integer.parseInt(raw.trim());
			return parsed > 0 ? parsed : defaultValue;
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	public static long parsePositiveLong(String raw, long defaultValue) {
		if (raw == null || raw.isBlank()) {
			return defaultValue;
		}
		try {
			long parsed = Long.parseLong(raw.trim());
			return parsed > 0 ? parsed : defaultValue;
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	public static String refreshMosipRequestTimestamp(String json) {
		if (json == null || json.isBlank()) {
			return json;
		}
		try {
			JSONObject body = new JSONObject(json);
			String now = generateCurrentUTCTimeStamp();
			if (body.has("requesttime")) {
				body.put("requesttime", now);
			}
			if (body.has("requestTime")) {
				body.put("requestTime", now);
			}
			return body.toString();
		} catch (JSONException e) {
			return json;
		}
	}

	public static boolean isStaleMosipRequestTime(Response response) {
		if (response == null) {
			return false;
		}
		try {
			return isStaleMosipRequestTime(response.asString());
		} catch (Exception e) {
			return false;
		}
	}

	static boolean isStaleMosipRequestTime(String body) {
		return body != null && (body.contains("IDR-IDC-002")
				|| body.contains("the timestamp value can be at most"));
	}

	public static final int PMS_PARTNER_ID_MAX_LENGTH = 36;

	public static String uniquePmsPartnerId() {
		return uniquePmsPartnerId(BaseTestCase.runContext, UUID.randomUUID().toString());
	}

	static String uniquePmsPartnerId(String runContext, String uuid) {
		String prefix = runContext == null ? "" : runContext.replaceAll("[^A-Za-z0-9]", "");
		if (prefix.length() > 4) {
			prefix = prefix.substring(0, 4);
		}
		String hex = uuid == null ? "" : uuid.replace("-", "");
		String id = prefix + hex;
		if (id.length() > PMS_PARTNER_ID_MAX_LENGTH) {
			return id.substring(0, PMS_PARTNER_ID_MAX_LENGTH);
		}
		return id.isEmpty() ? "p" + System.currentTimeMillis() : id;
	}

	public static String sanitizePmsPartnerSelfRegistration(String json) {
		if (json == null || json.isBlank() || !json.contains("\"partnerId\"")) {
			return json;
		}
		try {
			JSONObject body = new JSONObject(json);
			JSONObject request = body.optJSONObject("request");
			if (request == null || !request.has("partnerId")) {
				return json;
			}
			String partnerId = request.optString("partnerId", "");
			if (!partnerId.contains("$PARTNERID$") && partnerId.length() <= PMS_PARTNER_ID_MAX_LENGTH) {
				return json;
			}
			String pid = uniquePmsPartnerId();
			String organizationName = request.optString("organizationName", "");
			request.put("partnerId", pid);
			if (organizationName.contains("$PARTNERID$") || organizationName.equals(partnerId)) {
				request.put("organizationName", pid);
			}
			logger.info("Using PMS partnerId '" + pid + "' (max " + PMS_PARTNER_ID_MAX_LENGTH + ")");
			return body.toString();
		} catch (JSONException e) {
			return json;
		}
	}

	public static String refreshEsignetRequestTime(String json) {
		if (json == null || json.isBlank()) {
			return json;
		}
		try {
			JSONObject body = new JSONObject(json);
			body.put("requestTime", generateCurrentUTCTimeStamp());
			return body.toString();
		} catch (JSONException e) {
			return json;
		}
	}

	private static String replaceChallengeWithEmailOtp(String inputJson) {
		JSONObject request = new JSONObject(inputJson);
		if (request.has("otp")) {
			String otp = resolveEmailOtp(request.getString("otp"));
			if (otp != null) {
				request.put("otp", otp);
				return request.toString();
			}
			return inputJson;
		}
		if (!request.has(GlobalConstants.REQUEST)) {
			return inputJson;
		}
		JSONObject innerRequest = request.getJSONObject(GlobalConstants.REQUEST);
		if (innerRequest.has("otp")) {
			String otp = resolveEmailOtp(innerRequest.getString("otp"));
			if (otp != null) {
				innerRequest.put("otp", otp);
			}
			return request.toString();
		}
		if (innerRequest.has(GlobalConstants.CHALLENGELIST) && innerRequest.getJSONArray(GlobalConstants.CHALLENGELIST)
				.length() > 0
				&& innerRequest.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
						.has(GlobalConstants.CHALLENGE)) {
			String otp = resolveEmailOtp(innerRequest.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
					.getString(GlobalConstants.CHALLENGE));
			if (otp != null) {
				innerRequest.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0).put(GlobalConstants.CHALLENGE,
						otp);
			}
		}
		return request.toString();
	}

	private static final ThreadLocal<String> lastOtpMailbox = new ThreadLocal<>();

	private static String resolveEmailOtp(String challengeKey) {
		if (challengeKey == null) {
			return null;
		}
		if (!(challengeKey.endsWith(GlobalConstants.MOSIP_NET)
				|| challengeKey.endsWith(GlobalConstants.OTP_AS_PHONE))) {
			return null;
		}
		String emailId = challengeKey;
		if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE)) {
			emailId = removeLeadingPlusSigns(emailId.replace(GlobalConstants.OTP_AS_PHONE, ""));
		}
		logger.info(emailId);
		lastOtpMailbox.set(emailId);
		return NotificationListener.getOtp(emailId);
	}

	static boolean hasEmptyOtpChallenge(String json) {
		if (json == null || json.isBlank()) {
			return false;
		}
		try {
			JSONObject body = new JSONObject(json);
			if (body.has("otp") && body.getString("otp").isEmpty()) {
				return true;
			}
			if (!body.has(GlobalConstants.REQUEST)) {
				return false;
			}
			JSONObject request = body.getJSONObject(GlobalConstants.REQUEST);
			if (request.has("otp") && request.getString("otp").isEmpty()) {
				return true;
			}
			if (!request.has(GlobalConstants.CHALLENGELIST)) {
				return false;
			}
			JSONArray challenges = request.getJSONArray(GlobalConstants.CHALLENGELIST);
			for (int i = 0; i < challenges.length(); i++) {
				JSONObject challenge = challenges.getJSONObject(i);
				if (challenge.has(GlobalConstants.CHALLENGE)
						&& challenge.getString(GlobalConstants.CHALLENGE).isEmpty()) {
					return true;
				}
			}
			return false;
		} catch (JSONException e) {
			return false;
		}
	}

	/**
	 * Mock-SMTP endpoint {@code OTPListener} derives from the IAM host, repeated
	 * here so a missing OTP names the mailbox server the operator has to check.
	 */
	static String mockSmtpWebSocketUrl() {
		try {
			String host = URI.create(InjiCertifyConfigManager.getIAMUrl()).getHost();
			int firstDot = host == null ? -1 : host.indexOf('.');
			if (firstDot > -1 && firstDot < host.length() - 1) {
				return "wss://smtp." + host.substring(firstDot + 1) + "/mocksmtp/websocket";
			}
		} catch (RuntimeException ignored) {
			// Unit tests may call this before ConfigManager.init().
		}
		return "the mock-SMTP websocket";
	}

	/**
	 * eSignet answers {@code invalid_challenge} for an empty OTP, which buries the
	 * real cause and still burns the oauth-details transaction that the auth-code
	 * tests downstream depend on. Fail here instead, naming the mailbox.
	 */
	public static void requireResolvedOtpChallenge(String inputJson) throws AdminTestException {
		if (!hasEmptyOtpChallenge(inputJson)) {
			return;
		}
		String mailbox = lastOtpMailbox.get();
		throw new AdminTestException("No OTP arrived for "
				+ (mailbox == null || mailbox.isBlank() ? "the test mailbox" : mailbox)
				+ " within the OTP expiry window. send-otp succeeded, so IDA accepted the request and reported"
				+ " delivery; the notification never reached " + mockSmtpWebSocketUrl()
				+ ". Check the notification service and mock-SMTP on that cluster. Posting an empty challenge"
				+ " would only surface as invalid_challenge.");
	}
	
	protected static final String OIDCJWK1 = "oidcJWK1";
	protected static final String OIDCJWK4 = "oidcJWK4";
	private static final String OIDC_JWK_DPOP = "oidcJWKDpop";
	private static final String DPOP_WALLET_KEY = "dpopWalletJwk";
	private static final String DPOP_CASE_MARKER = "_DPoP_";
	private static RSAKey dpopWalletKey;
	private static final Map<String, String> oidcJwkStore = new HashMap<>();
	
	protected static boolean triggerESignetKeyGen1 = true;
	protected static boolean triggerESignetKeyGen13 = true;

	protected static RSAKey oidcJWKKey1 = null;
	protected static RSAKey oidcJWKKey4 = null;
	
	public static String clientAssertionToken;
	
	private static boolean gettriggerESignetKeyGen1() {
		return triggerESignetKeyGen1;
	}
	
	private static void settriggerESignetKeyGen1(boolean value) {
		triggerESignetKeyGen1 = value;
	}
	
	private static void settriggerESignetKeyGen13(boolean value) {
		triggerESignetKeyGen13 = value;
	}

	private static boolean gettriggerESignetKeyGen13() {
		return triggerESignetKeyGen13;
	}

	static String generateUniqueOidcJwkKey(String keyName) {
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2048, new SecureRandom());
			KeyPair keyPair = keyGenerator.generateKeyPair();
			RSAKey unique = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
					.privateKey(keyPair.getPrivate())
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.RS256)
					.keyID(keyName + "-" + UUID.randomUUID())
					.build();
			String json = unique.toJSONString();
			oidcJwkStore.put(keyName, json);
			logger.info("Generated unique OIDC JWK kid for " + keyName + ": " + unique.getKeyID());
			return json;
		} catch (Exception e) {
			logger.warn("Could not generate unique OIDC JWK for " + keyName + ": " + e.getMessage());
			String generated = JWKKeyUtil.generateAndCacheJWKKey(keyName);
			oidcJwkStore.put(keyName, generated);
			return generated;
		}
	}

	static String getOidcJwkKey(String keyName) {
		String stored = oidcJwkStore.get(keyName);
		return stored != null ? stored : JWKKeyUtil.getJWKKey(keyName);
	}

	static String toPublicOidcJwkJson(String jwkJson) {
		if (jwkJson == null || jwkJson.isBlank()) {
			return jwkJson;
		}
		try {
			RSAKey parsed = RSAKey.parse(jwkJson);
			return new RSAKey.Builder(parsed.toRSAPublicKey())
					.keyUse(KeyUse.SIGNATURE)
					.algorithm(JWSAlgorithm.RS256)
					.keyID(parsed.getKeyID())
					.build()
					.toJSONString();
		} catch (Exception e) {
			logger.warn("Could not convert OIDC JWK to public-only JSON: " + e.getMessage());
			return jwkJson;
		}
	}

	protected static final String BINDINGJWK1 = "bindingJWK1";

	public String inputStringKeyWordHandeler(String jsonString, String testCaseName) {
		if (jsonString != null && jsonString.contains("\"vpTestData\"")) {
			JSONObject request = new JSONObject(jsonString);
			if (request.has("vpTestData")) {
				request.remove("vpTestData");
				jsonString = request.toString();
			}
		}

		if (jsonString.contains("$CA_CERT$")) {
			JSONObject request = new JSONObject(jsonString);
			String csrCert = "";
			String signedCert = "";
			String algorithm = "RSA";
			String cafilename = "CertifyCA";

			if (request.has("csrCert")) {
				csrCert = request.getString("csrCert");
				request.remove("csrCert");
			}
			if (request.has("algorithm")) {
				algorithm = request.getString("algorithm");
				request.remove("algorithm");
			}
			if (request.has("cafilename")) {
				cafilename = request.getString("cafilename");
				request.remove("cafilename");
			}
			jsonString = request.toString();

			try {
				signedCert = signCsrAndGenerateCert("RSA Organization Automation", csrCert, algorithm, cafilename);
			} catch (Exception e) {

			}
			jsonString = replaceKeywordValue(jsonString, "$CA_CERT$", signedCert);
		}

		if (jsonString.contains("$ID:")) {
			jsonString = replaceIdWithAutogeneratedId(jsonString, "$ID:");
		}
		
		if (jsonString.contains("$FETCH_ID_FROM_CSV$")) {

			String csvUrl = getValueFromCertifyActuator(
					InjiCertifyConfigManager.getproperty("certifyActuatorPropertySection"),
					"mosip.certify.mock.data-provider.csv-registry-uri");

			String id = getIdFromCsvUrl(csvUrl);
			logger.info("Fetched ID from CSV");

			if (id == null) {
				logger.error("ID fetched from CSV is null");
			}

			jsonString = jsonString.replace("$FETCH_ID_FROM_CSV$", id);
		}
		
		if (jsonString.contains("$offer_id$")) {
			JSONObject request = new JSONObject(jsonString);
			String credeuri = "";

			if (request.has("credeuri")) {
				credeuri = request.getString("credeuri");
				request.remove("credeuri");
			}
			jsonString = request.toString();
			String offerId = extractOfferIdFromCredeUri(credeuri);
			jsonString = replaceKeywordValue(jsonString, "$offer_id$", offerId);

		}
			
		
		if (jsonString.contains("$SUNBIRDINSURANCEAUTHFACTORTYPE$")) {
			String authFactorType = InjiCertifyConfigManager
					.getproperty(InjiCertifyConstants.SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE_STRING);

			String valueToReplace = (authFactorType != null && !authFactorType.isBlank()) ? authFactorType
					: InjiCertifyConstants.SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE;

			jsonString = replaceKeywordValue(jsonString, "$SUNBIRDINSURANCEAUTHFACTORTYPE$", valueToReplace);

		}
		
		if (jsonString.contains("$UNIQUENONCEVALUE$")) {
			jsonString = replaceKeywordValue(jsonString, "$UNIQUENONCEVALUE$",
					String.valueOf(Calendar.getInstance().getTimeInMillis()));
		}
		
		if (jsonString.contains("$VCICONTEXTURL$")) {
			jsonString = replaceKeywordWithValue(jsonString, "$VCICONTEXTURL$",
					properties.getProperty("vciContextURL"));
		}
		
		if (jsonString.contains("$VCICONTEXTURL_2.0$")) {
			jsonString = replaceKeywordWithValue(jsonString, "$VCICONTEXTURL_2.0$",
					properties.getProperty("vciContextURL2"));
		}

		if (jsonString.contains("$KYCEXCHANGE_LOCALES$")) {
			jsonString = replaceKeywordValue(jsonString, "$KYCEXCHANGE_LOCALES$",
					resolveKycExchangeLocales(testCaseName));
		}

		if (jsonString.contains("$POLICYNUMBERFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$POLICYNUMBERFORSUNBIRDRC$", policyNumberForSunBirdR);
		}

		if (jsonString.contains("$FULLNAMEFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$FULLNAMEFORSUNBIRDRC$", fullNameForSunBirdR);
		}

		if (jsonString.contains("$DOBFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$DOBFORSUNBIRDRC$", dobForSunBirdR);
		}

		if (jsonString.contains("$CHALLENGEVALUEFORSUNBIRDC$")) {

			HashMap<String, String> mapForChallenge = new HashMap<String, String>();
			mapForChallenge.put(GlobalConstants.FULLNAME, fullNameForSunBirdR);
			mapForChallenge.put(GlobalConstants.DOB, dobForSunBirdR);

			String challenge = gson.toJson(mapForChallenge);

			String challengeValue = BiometricDataProvider.toBase64Url(challenge);

			jsonString = replaceKeywordValue(jsonString, "$CHALLENGEVALUEFORSUNBIRDC$", challengeValue);
		}

		if (jsonString.contains("$IDPREDIRECTURI$")) {
			jsonString = replaceKeywordValue(jsonString, "$IDPREDIRECTURI$",
					ApplnURI.replace(GlobalConstants.API_INTERNAL, "healthservices") + "/userprofile");
		}

		if (jsonString.contains("$OPENID4VP_RESPONSE$")) {
			JSONObject openId4VpRequest = resolveOpenId4VpRequest();
			JSONObject request = new JSONObject(jsonString);
			request.remove("openid4vp_request");
			JSONObject openId4VpResponse = PresentationDuringIssuanceVpUtil.buildOpenId4VpResponse(openId4VpRequest);
			jsonString = buildMdocvpIarRequestWire(request.getString("auth_session"),
					serializeJson(openId4VpResponse), request.optString("client_id", null));
		}

		if (jsonString.contains("$OIDCJWKKEY$")) {
			String jwkKey = "";
			if (gettriggerESignetKeyGen1()) {
				jwkKey = generateUniqueOidcJwkKey(OIDCJWK1);
				settriggerESignetKeyGen1(false);
			} else {
				jwkKey = getOidcJwkKey(OIDCJWK1);
			}
			jsonString = replaceKeywordValue(jsonString, "$OIDCJWKKEY$", toPublicOidcJwkJson(jwkKey));
		}
		
		if (jsonString.contains("$PROOF_JWT$")) {
			JWKKeyUtil.generateAndCacheJWKKey(BINDINGJWK1);
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK1);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey1 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey1 =" + oidcJWKKey1);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT$",
					signJWKForMockID(clientId, accessToken, cNonce, oidcJWKKey1, testCaseName, tempUrl));
		}		

		if (jsonString.contains("$OIDCJWKKEY4$")) {
			String jwkKey = "";
			if (gettriggerESignetKeyGen13()) {
				jwkKey = generateUniqueOidcJwkKey(OIDCJWK4);
				settriggerESignetKeyGen13(false);
			} else {
				jwkKey = getOidcJwkKey(OIDCJWK4);
			}
			jsonString = replaceKeywordValue(jsonString, "$OIDCJWKKEY4$", toPublicOidcJwkJson(jwkKey));
		}

		if (jsonString.contains("$OIDCJWKKEY_DPOP$")) {
			if (oidcJwkStore.get(OIDC_JWK_DPOP) == null) {
				generateUniqueOidcJwkKey(OIDC_JWK_DPOP);
			}
			jsonString = replaceKeywordValue(jsonString, "$OIDCJWKKEY_DPOP$",
					toPublicOidcJwkJson(oidcJwkStore.get(OIDC_JWK_DPOP)));
		}
		if (jsonString.contains("$PROOF_JWT_3$")) {
			JWKKeyUtil.generateAndCacheJWKKey(BINDINGJWK1);
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK4);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey4 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey4 =" + oidcJWKKey4);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}

			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_3$",
					signJWKForMockID(clientId, accessToken, cNonce, oidcJWKKey4, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("$PROOF_JWT_ED25519$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ED25519$",
					signED25519JWT(clientId, accessToken, cNonce, testCaseName, tempUrl));
		}

		if (jsonString.contains("$PROOF_JWT_PDI_HOLDER$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			try {
				OctetKeyPair holderKey = PresentationDuringIssuanceVpUtil.pdiHolderOctetKeyPair();
				String tempUrl = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
						getMosipIdCertifyBaseUrl());
				jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_PDI_HOLDER$",
						signED25519JWTWithHolderJwk(clientId, accessToken, cNonce, tempUrl, holderKey));
			} catch (Exception e) {
				throw new RuntimeException("Failed to sign PDI holder proof JWT for Mosip ID GetCredential", e);
			}
		}
		
		if (jsonString.contains("$PROOF_JWT_ES256$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ES256$",
					signES256JWT(clientId, accessToken, cNonce, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("$PROOF_JWT_ES256K$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ES256K$",
					signES256KJWT(clientId, accessToken, cNonce, testCaseName, tempUrl));
		}

		if (jsonString.contains("$CLIENT_ASSERTION_JWT$")) {
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK1);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey1 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey1 =" + oidcJWKKey1);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}
			JSONObject request = new JSONObject(jsonString);
			String clientId = null;
			if (request.has("client_id")) {
				clientId = request.get("client_id").toString();
			}
			String tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());
			jsonString = replaceKeywordValue(jsonString, "$CLIENT_ASSERTION_JWT$",
					signJWKKey(clientId, oidcJWKKey1, tempUrl));
		}

		if (jsonString.contains("$CLIENT_ASSERTION_USER4_JWT$")) {
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK4);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey4 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey4 =" + oidcJWKKey4);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}
			JSONObject request = new JSONObject(jsonString);
			String clientId = null;
			if (request.has("client_id")) {
				clientId = request.get("client_id").toString();
			}
			String tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$CLIENT_ASSERTION_USER4_JWT$",
					signJWKKey(clientId, oidcJWKKey4, tempUrl));
		}

		if (jsonString.contains("$CLIENT_ASSERTION_DPOP_JWT$")) {
			String storedDpopJwk = oidcJwkStore.get(OIDC_JWK_DPOP);
			if (storedDpopJwk == null || storedDpopJwk.isBlank()) {
				throw new SkipException(
						"DPoP client key is not available. Ensure the DPoP OIDC client case ran before this token request.");
			}
			RSAKey dpopClientKey;
			try {
				dpopClientKey = RSAKey.parse(storedDpopJwk);
			} catch (java.text.ParseException e) {
				throw new SkipException(
						"DPoP client key could not be parsed. Ensure the DPoP OIDC client case ran before this token request.");
			}
			JSONObject request = new JSONObject(jsonString);
			String clientId = null;
			if (request.has("client_id")) {
				clientId = request.get("client_id").toString();
			}
			String tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());
			jsonString = replaceKeywordValue(jsonString, "$CLIENT_ASSERTION_DPOP_JWT$",
					signJWKKey(clientId, dpopClientKey, tempUrl));
		}

		if (jsonString.contains("$CLIENT_ASSERTION_USER4_JWK$")) {
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK4);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey4 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey4 =" + oidcJWKKey4);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}
			JSONObject request = new JSONObject(jsonString);
			String clientId = null;
			if (request.has("client_id")) {
				clientId = request.get("client_id").toString();
			}
			jsonString = replaceKeywordValue(jsonString, "$CLIENT_ASSERTION_USER4_JWK$",
					signJWKKeyForMock(clientId, oidcJWKKey4));
		}

		if (jsonString.contains("$PROOF_JWT_2$")) {
			JWKKeyUtil.generateAndCacheJWKKey(BINDINGJWK1);
			String oidcJWKKeyString = getOidcJwkKey(OIDCJWK4);
			logger.info("oidcJWKKeyString =" + oidcJWKKeyString);
			try {
				oidcJWKKey4 = RSAKey.parse(oidcJWKKeyString);
				logger.info("oidcJWKKey4 =" + oidcJWKKey4);
			} catch (java.text.ParseException e) {
				logger.error(e.getMessage());
			}

			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String cNonce = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			if (request.has("c_nonce")) {
				cNonce = request.getString("c_nonce");
				request.remove("c_nonce");
			}
			jsonString = request.toString();

			String baseURL = InjiCertifyConfigManager.getInjiCertifyBaseUrl();
			if (testCaseName.contains("_GetCredentialSunBirdC")) {
				tempUrl = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
			}
			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_2$",
					signJWKForMockID(clientId, accessToken, cNonce, oidcJWKKey4, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("indexedAttributesEquals")) {
			jsonString = normalizeIndexedAttributes(jsonString);
		}

		if (jsonString.contains("\"credential_configuration_id\"")) {
			try {
				JSONObject request = new JSONObject(jsonString);
				request.remove("c_nonce");
				jsonString = request.toString();
			} catch (Exception e) {
				logger.error("Failed to strip c_nonce from credential request: " + e.getMessage());
			}
		}

		jsonString = sanitizePmsPartnerSelfRegistration(jsonString);

		if (jsonString.contains(GlobalConstants.TIMESTAMP)) {
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
		}
		if (testCaseName == null || !testCaseName.contains("RequestTime_Neg")) {
			jsonString = refreshMosipRequestTimestamp(jsonString);
		}

		return jsonString;
	}

	private static final String CA_P12_FILE_NAME = "-ca.p12"; 
	private static int rpPartnerCertExpiryYears = 5;
	protected String signCsrAndGenerateCert(String organization, String csr, String algorithm, String filePrepend)
			throws OperatorCreationException, CertificateException, IOException, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableEntryException {
		CryptoCoreUtil cryptoCoreUtil = new CryptoCoreUtil();
		KeyMgrUtility keyMgrUtility = new KeyMgrUtility(cryptoCoreUtil);

		String dirPath = keyMgrUtility.getKeysDirPath(null, BaseTestCase.certsForModule,
				ApplnURI.replace("https://", ""));

		String caFilePath = dirPath + '/' + filePrepend + CA_P12_FILE_NAME;
		LocalDateTime dateTime = LocalDateTime.now();
		LocalDateTime dateTimeExp = dateTime.plusYears(rpPartnerCertExpiryYears);
		KeyStore.PrivateKeyEntry caPrivKeyEntry = keyMgrUtility.getPrivateKeyEntry(caFilePath);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign);
		caPrivKeyEntry = keyMgrUtility.generateKeys(null, "CA-" + filePrepend, "CA-" + filePrepend, caFilePath,
				keyUsage, dateTime, dateTimeExp, organization, algorithm);
		String caCertificate = keyMgrUtility.getCertificate(caPrivKeyEntry);

		PKCS10CertificationRequest csrCertificate = keyMgrUtility
				.parseCertificate(replaceIdWithAutogeneratedId(csr, "$ID:"));
		PrivateKey privateKey = caPrivKeyEntry.getPrivateKey();


		PublicKey publicKey = new JcaPEMKeyConverter().getPublicKey(csrCertificate.getSubjectPublicKeyInfo());
		String signAlgo = algorithm;

		X509Certificate signedCert = keyMgrUtility.generateX509Certificate(privateKey, publicKey, "CA", "SignCert",
				keyUsage, dateTime, dateTimeExp, organization, signAlgo);
		StringWriter sw = new StringWriter();
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
			pemWriter.writeObject(signedCert);
			pemWriter.flush();
		}
		
		// Convert the generated certificate (server/leaf certificate) into PEM format.
		String pemCert = sw.toString();
		
		// Store the signed certificate in the auto-generated test ID cache for later assertions/logging
		writeAutoGeneratedId(currentTestCaseName, "SignedCert", normalizePemForJson(pemCert));

		return normalizePemForJson(caCertificate);
	}
	
	
	
	public static String replaceKeywordValue(String jsonString, String keyword, String value) {
		if (value != null && !value.isEmpty())
			return jsonString.replace(keyword, value);
		else {
			if (keyword.contains("$ID:"))
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword
						+ " please check the results of testcase: " + getTestCaseIDFromKeyword(keyword));
			else
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword);

		}
	}
	
	public static Map<String, List<String>> proofSigningAlgorithmsMap = new HashMap<>();
	
	public static String getMosipIdCertifyBaseUrl() {
		String configured = InjiCertifyConfigManager.getproperty("injiCertifyMosipIdBaseURL");
		if (configured != null && !configured.isBlank()) {
			return configured.trim();
		}
		String baseUrl = InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		if (baseUrl.contains("-mdoc.")) {
			return baseUrl.replace("-mdoc.", "-mosipid.");
		}
		if (baseUrl.contains("-mdocvp.")) {
			return baseUrl.replace("-mdocvp.", "-mosipid.");
		}
		return baseUrl;
	}

	public static String getMosipIdEsignetBaseUrl() {
		String configured = InjiCertifyConfigManager.getproperty("eSignetMosipIdBaseUrl");
		if (configured != null && !configured.isBlank()) {
			return configured.trim();
		}
		String baseUrl = InjiCertifyConfigManager.getEsignetBaseUrl();
		if (baseUrl.contains("esignet-mock")) {
			return baseUrl.replace("esignet-mock", "esignet-mosipid");
		}
		return baseUrl;
	}

	public static void captureEsignetCsrf(Response response) {
		if (response == null) {
			return;
		}
		String cookie = response.getCookie(GlobalConstants.XSRF_TOKEN);
		String headerToken = response.getHeader("X-XSRF-TOKEN");
		String bodyToken = null;
		try {
			bodyToken = response.jsonPath().getString("token");
		} catch (Exception ignored) {
			// body may not be JSON or may omit token
		}
		if ((cookie == null || cookie.isBlank()) && (bodyToken == null || bodyToken.isBlank())
				&& (headerToken == null || headerToken.isBlank())) {
			return;
		}
		applyEsignetCsrfTokens(cookie, headerToken, bodyToken);
	}

	/**
	 * Spring Security 6 XOR CSRF uses two different values: the raw UUID in the
	 * {@code XSRF-TOKEN} cookie and the deferred token from {@code /csrf/token}
	 * JSON {@code token} in the {@code X-XSRF-TOKEN} header. Copying the cookie
	 * into the header is rejected with HTTP 403.
	 */
	public static void applyEsignetCsrfTokens(String cookie, String headerToken, String bodyToken) {
		if (bodyToken != null && !bodyToken.isBlank()) {
			BaseTestCase.CSRF_TOKEN = bodyToken;
		} else if (headerToken != null && !headerToken.isBlank()) {
			BaseTestCase.CSRF_TOKEN = headerToken;
		}
		if (cookie != null && !cookie.isBlank()) {
			BaseTestCase.CSRF_COOKIE = cookie;
		}
	}

	public static void fetchMosipIdCsrfTokenIfNeeded(String testCaseName) {
		if (isMosipIdTestName(testCaseName)) {
			fetchMosipIdCsrfToken();
		}
	}

	static final String DEFAULT_CSRF_TOKEN_ENDPOINT = "/v1/esignet/csrf/token";

	/**
	 * {@code ConfigManager.getproperty} answers "" for an absent key, so an unset
	 * {@code csrfTokenEndpoint} leaves the library concatenating nothing onto the
	 * eSignet base URL and fetching the UI root, which returns 200 text/html and
	 * then fails as JSON. Default the path so the property being missing cannot
	 * silently retarget the request at the UI.
	 */
	static String csrfTokenEndpointPath() {
		String endpoint = InjiCertifyConfigManager.getproperty("csrfTokenEndpoint");
		if (endpoint == null || endpoint.isBlank()) {
			endpoint = DEFAULT_CSRF_TOKEN_ENDPOINT;
		}
		if (!endpoint.startsWith("/")) {
			endpoint = "/" + endpoint;
		}
		return endpoint;
	}

	/**
	 * Every use case needs this, not just mosipid, else eSignet answers 403. Failing
	 * to get a token is worth an error but not an abort: the library version throws
	 * on a non-JSON body or a missing XSRF-TOKEN cookie, and thrown from the runner
	 * that ends the process before a single test runs, so the run produces no report
	 * at all rather than a report showing which tests the missing token broke.
	 */
	public static void fetchEsignetCsrfToken() {
		String url = InjiCertifyConfigManager.getEsignetBaseUrl().replaceAll("/+$", "") + csrfTokenEndpointPath();
		try {
			Response response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
			extractAndStoreCsrfToken(response);
			logger.info("Fetched eSignet CSRF cookie and XOR header token from " + url);
		} catch (Exception e) {
			logger.error("Could not fetch eSignet CSRF token from " + url
					+ "; eSignet may answer 403 Forbidden for tests that need one", e);
		}
	}

	public static void fetchMosipIdCsrfToken() {
		String url = getMosipIdEsignetBaseUrl().replaceAll("/+$", "") + csrfTokenEndpointPath();
		try {
			Response response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
			extractAndStoreCsrfToken(response);
			logger.info("Fetched Mosip ID eSignet CSRF cookie and XOR header token from " + url);
		} catch (Exception e) {
			logger.warn("Could not fetch Mosip ID eSignet CSRF token from " + url + ": " + e.getMessage());
		}
	}

	public static final String MOSIP_ID_FIXED_CREDENTIAL_CONFIG_KEY_ID = "MOSIPVerifiableCredential";
	public static boolean shouldReplaceExistingMosipIdCredentialConfig(TestCaseDTO testCaseDTO) {
		return testCaseDTO != null
				&& "TC_InjiCertify_MosipID_AddCredentialConfig_01".equals(testCaseDTO.getUniqueIdentifier());
	}

	public static boolean shouldUpdateExistingMosipIdCredentialConfig(TestCaseDTO testCaseDTO, Response response) {
		return shouldReplaceExistingMosipIdCredentialConfig(testCaseDTO)
				&& isDuplicateMosipIdCredentialConfig(response);
	}

	public static boolean isDuplicateMosipIdCredentialConfig(Response response) {
		if (response == null) {
			return false;
		}
		String body = "";
		try {
			body = response.getBody() != null ? response.getBody().asString() : "";
		} catch (Exception e) {
			logger.warn("Could not read Certify response body: " + e.getMessage());
		}
		return isDuplicateMosipIdCredentialConfigBody(body);
	}

	static boolean isDuplicateMosipIdCredentialConfigBody(String body) {
		if (body == null || body.isBlank()) {
			return false;
		}
		try {
			JSONArray errors = new JSONObject(body).optJSONArray("errors");
			if (errors == null) {
				return false;
			}
			for (int i = 0; i < errors.length(); i++) {
				JSONObject error = errors.getJSONObject(i);
				String errorCode = error.optString("errorCode");
				if ("ldp_vc_config_exists".equals(errorCode)) {
					return true;
				}
				if ("unknown_error".equals(errorCode) && looksLikeDuplicateCredentialConfigKey(error)) {
					return true;
				}
				logger.warn("AddCredentialConfig errorCode=" + errorCode + " message="
						+ error.optString("errorMessage"));
			}
		} catch (Exception e) {
			logger.warn("Could not parse Certify duplicate-config body: " + e.getMessage());
		}
		return false;
	}

	static boolean looksLikeDuplicateCredentialConfigKey(JSONObject error) {
		if (error == null) {
			return false;
		}
		String message = (error.optString("errorMessage") + " " + error.optString("message")).toLowerCase(Locale.ROOT);
		return message.contains("uk_credential_config_key_id") || message.contains("duplicate key")
				|| message.contains("already exists");
	}

	public static String alignMosipIdCredentialTypeForPresentationDuringIssuance(TestCaseDTO testCaseDTO,
			String requestJson) {
		if (requestJson == null || requestJson.isBlank() || !isMdocvpMosipIdPrerequisite(testCaseDTO)
				|| !shouldReplaceExistingMosipIdCredentialConfig(testCaseDTO)) {
			return requestJson;
		}
		logger.info("Aligning Mosip ID credential type and config id to MOSIPVerifiableCredential for Presentation During Issuance");
		String aligned = replaceMosipIdCredentialType(requestJson, "MOSIPVerifiableCredential_automation",
				"MOSIPVerifiableCredential");
		aligned = applyMosipIdPdiCredentialConfigKeyId(aligned);
		aligned = replaceMosipIdV1DateFields(aligned);
		return alignMosipIdDidUrlForPresentationDuringIssuance(aligned);
	}

	static String applyMosipIdPdiCredentialConfigKeyId(String requestJson) {
		JSONObject request = new JSONObject(requestJson);
		request.put("credentialConfigKeyId", MOSIP_ID_FIXED_CREDENTIAL_CONFIG_KEY_ID);
		return request.toString();
	}

	static String replaceMosipIdV1DateFields(String requestJson) {
		JSONObject request = new JSONObject(requestJson);
		replaceVcTemplateJsonPropertyName(request, "validFrom", "issuanceDate");
		replaceVcTemplateJsonPropertyName(request, "validUntil", "expirationDate");
		logger.info("Aligned Mosip ID VC template dates to issuanceDate/expirationDate for credentials v1");
		return request.toString();
	}

	static String alignMosipIdDidUrlForPresentationDuringIssuance(String requestJson) {
		String issuerDid = resolveMosipIdIssuerDid();
		if (issuerDid == null || issuerDid.isBlank()) {
			logger.warn("Could not resolve Mosip ID issuer DID; leaving credential config didUrl unchanged");
			return requestJson;
		}
		logger.info("Aligning Mosip ID credential config didUrl to issuer DID " + issuerDid);
		return replaceMosipIdDidUrl(requestJson, issuerDid);
	}

	static String replaceMosipIdDidUrl(String requestJson, String didUrl) {
		JSONObject request = new JSONObject(requestJson);
		request.put("didUrl", didUrl);
		return request.toString();
	}

	static String resolveMosipIdIssuerDid() {
		String baseUrl = getMosipIdCertifyBaseUrl();
		if (baseUrl == null || baseUrl.isBlank()) {
			return "";
		}
		String trimmed = baseUrl.replaceAll("/+$", "");
		for (String url : List.of(trimmed + "/.well-known/did.json", trimmed + "/v1/certify/.well-known/did.json")) {
			try {
				Response response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
				if (response != null && response.getStatusCode() == 200 && response.getBody() != null) {
					String did = new JSONObject(response.getBody().asString()).optString("id", "");
					if (did.startsWith("did:")) {
						return did;
					}
				}
			} catch (Exception e) {
				logger.warn("Could not load Mosip ID DID document from " + url + ": " + e.getMessage());
			}
		}
		try {
			String host = URI.create(trimmed).getHost();
			if (host != null && !host.isBlank()) {
				return "did:web:" + host;
			}
		} catch (Exception e) {
			logger.warn("Could not derive Mosip ID did:web from " + trimmed + ": " + e.getMessage());
		}
		return "";
	}

	static String replaceMosipIdCredentialType(String requestJson, String oldType, String newType) {
		JSONObject request = new JSONObject(requestJson);
		replaceCredentialTypeValue(request, "credentialTypes", oldType, newType);
		replaceCredentialTypeValue(request, "type", oldType, newType);
		replaceVcTemplateCredentialType(request, oldType, newType);
		return request.toString();
	}

	private static void replaceCredentialTypeValue(JSONObject request, String arrayField, String oldType,
			String newType) {
		if (!request.has(arrayField)) {
			return;
		}
		JSONArray types = request.getJSONArray(arrayField);
		JSONArray updated = new JSONArray();
		for (int i = 0; i < types.length(); i++) {
			Object item = types.get(i);
			if (item instanceof String) {
				updated.put(oldType.equals(item) ? newType : item);
			} else if (item instanceof JSONObject) {
				JSONObject obj = (JSONObject) item;
				if (oldType.equals(obj.optString("credentialTypes"))) {
					obj.put("credentialTypes", newType);
				}
				if (oldType.equals(obj.optString("type_value"))) {
					obj.put("type_value", newType);
				}
				updated.put(obj);
			} else {
				updated.put(item);
			}
		}
		request.put(arrayField, updated);
	}

	private static void replaceVcTemplateCredentialType(JSONObject request, String oldType, String newType) {
		if (!request.has("vcTemplate")) {
			return;
		}
		Object templateObj = request.get("vcTemplate");
		if (templateObj instanceof JSONObject) {
			String quotedOld = "\"" + oldType + "\"";
			String quotedNew = "\"" + newType + "\"";
			String patched = templateObj.toString().replace(quotedOld, quotedNew);
			request.put("vcTemplate", new JSONObject(patched));
			return;
		}
		String raw = String.valueOf(templateObj);
		String decoded = maybeDecodeVcTemplate(raw);
		String quotedOld = "\"" + oldType + "\"";
		String quotedNew = "\"" + newType + "\"";
		String patched = decoded.replace(quotedOld, quotedNew);
		if (!decoded.equals(raw)) {
			request.put("vcTemplate", AdminTestUtil.encodeBase64(patched));
		} else {
			request.put("vcTemplate", patched);
		}
	}

	private static void replaceVcTemplateJsonPropertyName(JSONObject request, String oldName, String newName) {
		if (!request.has("vcTemplate")) {
			return;
		}
		String oldKey = "\"" + oldName + "\":";
		String newKey = "\"" + newName + "\":";
		Object templateObj = request.get("vcTemplate");
		if (templateObj instanceof JSONObject) {
			String patched = templateObj.toString().replace(oldKey, newKey);
			request.put("vcTemplate", new JSONObject(patched));
			return;
		}
		String raw = String.valueOf(templateObj);
		String decoded = maybeDecodeVcTemplate(raw);
		String patched = decoded.replace(oldKey, newKey);
		if (!decoded.equals(raw)) {
			request.put("vcTemplate", AdminTestUtil.encodeBase64(patched));
		} else {
			request.put("vcTemplate", patched);
		}
	}

	private static String maybeDecodeVcTemplate(String value) {
		if (value == null) {
			return "";
		}
		String trimmed = value.trim();
		if (trimmed.startsWith("{") || trimmed.contains("MOSIPVerifiableCredential_automation")) {
			return value;
		}
		try {
			String decoded = new String(Base64.getDecoder().decode(trimmed), StandardCharsets.UTF_8);
			if (decoded.contains("MOSIPVerifiableCredential") || decoded.trim().startsWith("{")) {
				return decoded;
			}
		} catch (IllegalArgumentException ignored) {
		}
		return value;
	}

	public static String getJsonFromInjiCertifyWellKnownEndPoint() {
		return getJsonFromInjiCertifyWellKnownEndPoint(InjiCertifyConfigManager.getInjiCertifyBaseUrl());
	}

	public static String getJsonFromInjiCertifyWellKnownEndPoint(String certifyBaseUrl) {
		String url = certifyBaseUrl + InjiCertifyConfigManager.getproperty("injiCertifyWellKnownEndPoint");

		Response response = null;
		try {
			response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);

		} catch (Exception e) {
			logger.error("Exception while making the request to the Inji Certify well-known endpoint: ", e);
		}

		if (response != null && response.getBody() != null) {
			return response.getBody().asString();
		} else {
			logger.warn("No response or empty body received from the Inji Certify well-known endpoint.");
			return "";
		}
	}
	
	public static void getSupportedCredentialSigningAlg() {
		String jsonResponse = getJsonFromInjiCertifyWellKnownEndPoint();

		if (jsonResponse != null && jsonResponse.isBlank() == false) {
			fetchAndUpdateSupportedAlgValues(jsonResponse);
		}

		logger.info("proofSigningAlgorithmsMap = " + proofSigningAlgorithmsMap);

	}

	public static void fetchAndUpdateSupportedAlgValues(String json) {
		ObjectMapper objectMapper = new ObjectMapper();

		try {
			JsonNode rootNode = objectMapper.readTree(json);
			JsonNode credentialConfigurationsNode = rootNode.path("credential_configurations_supported");

			// Iterate over each credential configuration and extract the signing algorithms
			Iterator<String> fieldNames = credentialConfigurationsNode.fieldNames();
			while (fieldNames.hasNext()) {
				String credentialType = fieldNames.next();
				JsonNode credentialConfigNode = credentialConfigurationsNode.path(credentialType);

				// Extract the proof_signing_alg_values_supported field
				JsonNode proofSigningAlgorithmsNode = credentialConfigNode.path("proof_types_supported").path("jwt")
						.path("proof_signing_alg_values_supported");

				if (proofSigningAlgorithmsNode.isArray()) {
					// Initialize list to store proof signing algorithms
					List<String> proofSigningAlgorithms = new ArrayList<>();
					for (JsonNode algNode : proofSigningAlgorithmsNode) {
						proofSigningAlgorithms.add(algNode.asText());
					}

					if (!proofSigningAlgorithms.isEmpty()) {
						proofSigningAlgorithmsMap.put(credentialType, proofSigningAlgorithms);
					}
				}
			}

		} catch (IOException e) {
			logger.error("Error while processing JSON: " + e.getMessage());
		}
	}
	
	public static String getValueFromInjiCertifyWellKnownEndPoint(String key, String baseURL) {
		String url = baseURL + InjiCertifyConfigManager.getproperty("injiCertifyWellKnownEndPoint");

		String actuatorCacheKey = url + key;
		String value = actuatorValueCache.get(actuatorCacheKey);
		if (value != null && !value.isEmpty())
			return value;

		Response response = null;
		JSONObject responseJson = null;
		try {
			response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
			responseJson = new org.json.JSONObject(response.getBody().asString());
			if (responseJson.has(key)) {
				actuatorValueCache.put(actuatorCacheKey, responseJson.getString(key));
				return responseJson.getString(key);
			}
		} catch (Exception e) {
			logger.error(GlobalConstants.EXCEPTION_STRING_2 + e);
		}
		return responseJson.getString(key);
	}
	
	public static String signJWKKeyForMock(String clientId, RSAKey jwkKey) {
		String tempUrl = getValueFromEsignetWellKnownEndPoint("token_endpoint", InjiCertifyConfigManager.getEsignetBaseUrl());
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		JWSSigner signer;

		try {
			signer = new RSASSASigner(jwkKey);

			Date currentTime = new Date();

			// Create a Calendar instance to manipulate time
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);

			// Add one hour to the current time
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600)); // Adding one hour

			// Get the updated expiration time
			Date expirationTime = calendar.getTime();

			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(clientId).audience(tempUrl).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();

			logger.info("JWT current and expiry time " + currentTime + " & " + expirationTime);

			SignedJWT signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwkKey.getKeyID()).build(), claimsSet);

			signedJWT.sign(signer);
			clientAssertionToken = signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing oidcJWKKey for client assertion: " + e.getMessage());
		}
		return clientAssertionToken;
	}
	
	public static String signJWKForMock(String clientId, String accessToken, RSAKey jwkKey, String testCaseName,
			String tempUrl) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		JWSSigner signer;
		String proofJWT = "";
		String typ = "openid4vci-proof+jwt";
		JWK jwkHeader = jwkKey.toPublicJWK();
		SignedJWT signedJWT = null;

		try {
			signer = new RSASSASigner(jwkKey);
			Date currentTime = new Date();

			// Create a Calendar instance to manipulate time
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);

			// Add one hour to the current time
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600)); // Adding one hour

			// Get the updated expiration time
			Date expirationTime = calendar.getTime();

			String[] jwtParts = accessToken.split("\\.");
			String jwtPayloadBase64 = jwtParts[1];
			byte[] jwtPayloadBytes = Base64.getDecoder().decode(jwtPayloadBase64);
			String jwtPayload = new String(jwtPayloadBytes, StandardCharsets.UTF_8);
			JWTClaimsSet claimsSet = null;
			String nonce = new ObjectMapper().readTree(jwtPayload).get("c_nonce").asText();

			claimsSet = new JWTClaimsSet.Builder().audience(tempUrl).claim("nonce", nonce).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();
			signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(typ)).jwk(jwkHeader).build(),
					claimsSet);

			signedJWT.sign(signer);
			proofJWT = signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt to get credential: " + e.getMessage());
		}
		return proofJWT;
	}
	
	public static String signJWKKey(String clientId, RSAKey jwkKey, String tempUrl) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		JWSSigner signer;

		try {
			signer = new RSASSASigner(jwkKey);

			Date currentTime = new Date();

			// Create a Calendar instance to manipulate time
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);

			// Add one hour to the current time
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600)); // Adding one hour

			// Get the updated expiration time
			Date expirationTime = calendar.getTime();

			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(clientId).audience(tempUrl).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();

			logger.info("JWT current and expiry time " + currentTime + " & " + expirationTime);

			SignedJWT signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwkKey.getKeyID()).build(), claimsSet);

			signedJWT.sign(signer);
			clientAssertionToken = signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing oidcJWKKey for client assertion: " + e.getMessage());
		}
		return clientAssertionToken;
	}
	
	public static String getValueFromEsignetWellKnownEndPoint(String key, String baseURL) {
		String url = baseURL + InjiCertifyConfigManager.getproperty("esignetWellKnownEndPoint");
		Response response = null;
		JSONObject responseJson = null;
		if (responseJson == null) {
			try {
				response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
				responseJson = new org.json.JSONObject(response.getBody().asString());
				return responseJson.getString(key);
			} catch (Exception e) {
				logger.error(GlobalConstants.EXCEPTION_STRING_2 + e);
			}
		}
		return responseJson.getString(key);
	}
	
	public static String getBaseURL(String testCaseName, String baseURL) {
		String tempURL = "";

		if (testCaseName.contains("_GetCredentialMosipID") || testCaseName.contains("MosipID_GenerateNonce")) {
			baseURL = getMosipIdCertifyBaseUrl();
		}

		if (testCaseName.contains("_GetCredentialSunBirdC")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GetCredentialMosipID")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GenerateTokenVCIMOSIPID")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint", getMosipIdEsignetBaseUrl());
		} else if (testCaseName.contains("_GenerateToken_ForMockIDA")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GenerateToken_ForLandRegistry")|| testCaseName.contains("_GenerateToken_Formdl")
				|| testCaseName.contains("_GenerateTokenSunBirdC")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GetCredentialForMockIDA")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GetCredentialForLandRegistry")|| testCaseName.contains("_GetCredentialFormdl") || testCaseName.contains("_GetCredentialFormdocvp")|| testCaseName.contains("_GetCredentialForPreAuthCode")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		}

		return tempURL;

	}
	
	public static String getTempURL(TestCaseDTO testCaseDTO) {
		return getTempURL(testCaseDTO, null);
	}
	
	public static String getTempURL(TestCaseDTO testCaseDTO, String endPoint) {
		String testCaseName = testCaseDTO.getTestCaseName();

		if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOCKBASEURL$") && testCaseName.contains("SunBirdC")) {
			if (InjiCertifyConfigManager.isInServiceNotDeployedList("sunbirdrc"))
				throw new SkipException(GlobalConstants.SERVICE_NOT_DEPLOYED_MESSAGE);

			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOSIPIDBASEURL$")) {
			return getMosipIdEsignetBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOSIPIDBASEURL$")) {
			return getMosipIdEsignetBaseUrl();
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
				&& testCaseName.contains("GetCredentialSunBirdC")) {
			return InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
				&& testCaseName.contains("SunBirdC_GenerateNonce")) {
			return InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
				&& testCaseName.contains("CredentialConfig")) {
			return InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOSIPIDBASEURL$")) {
			return getMosipIdCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOCKIDABASEURL$")
				&& (testCaseName.contains("_GetCredentialForMockIDA")
						|| testCaseName.contains("MockIDA_GenerateNonce"))) {
			return InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$SUNBIRDBASEURL$")
				&& testCaseName.contains("Policy_")) {
			return InjiCertifyConfigManager.getSunBirdBaseURL();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYBASEURL$")) {
			if (isMosipIdTestName(testCaseName)) {
				return getMosipIdCertifyBaseUrl();
			}
			return InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		}
		
		

		return endPoint == null ? testCaseDTO.getEndPoint() : endPoint;
	}
	
	public static String getKeyWordFromEndPoint(String endPoint) {
		
		if (endPoint.startsWith("$ESIGNETMOCKBASEURL$"))
			return "$ESIGNETMOCKBASEURL$";
		if (endPoint.startsWith("$ESIGNETMOSIPIDBASEURL$"))
			return "$ESIGNETMOSIPIDBASEURL$";
		if (endPoint.startsWith("$ESIGNETMOCKIDABASEURL$"))
			return "$ESIGNETMOCKIDABASEURL$";
		if (endPoint.startsWith("$INJICERTIFYINSURANCEBASEURL$"))
			return "$INJICERTIFYINSURANCEBASEURL$";
		if (endPoint.startsWith("$INJICERTIFYMOSIPIDBASEURL$"))
			return "$INJICERTIFYMOSIPIDBASEURL$";
		if (endPoint.startsWith("$INJICERTIFYMOCKIDABASEURL$"))
			return "$INJICERTIFYMOCKIDABASEURL$";
		if (endPoint.startsWith("$SUNBIRDBASEURL$"))
			return "$SUNBIRDBASEURL$";
		if (endPoint.startsWith("$INJICERTIFYBASEURL$"))
			return "$INJICERTIFYBASEURL$";
		
		return "";
	}

	@Override
	protected Response postWithBodyAndCookieForAutoGeneratedIdForUrlEncoded(String url, String jsonInput,
			String testCaseName, String idKeyName) throws SecurityXSSException {
		if (!isDpopCase(testCaseName)) {
			return super.postWithBodyAndCookieForAutoGeneratedIdForUrlEncoded(url, jsonInput, testCaseName, idKeyName);
		}
		String resolved = inputJsonKeyWordHandeler(jsonInput, testCaseName);
		Map<String, String> form = jsonToForm(resolved);
		Response response = postDpopForm(url, form, null);
		if (response != null && response.asString() != null && response.asString().contains("use_dpop_nonce")) {
			response = postDpopForm(url, form, response.getHeader("DPoP-Nonce"));
		}
		if (response != null) {
			GlobalMethods.checkXSSProtectionHeader(response, url);
			GlobalMethods.reportResponse(response.getHeaders().asList().toString(), url, response);
			if (testCaseName.toLowerCase().contains("_sid")) {
				writeAutoGeneratedId(response, idKeyName, testCaseName);
			}
		}
		return response;
	}

	@Override
	protected Response postRequestWithCookieAuthHeaderAndXsrfToken(String url, String jsonInput, String cookieName,
			String testCaseName) throws SecurityXSSException {
		if (!isDpopCase(testCaseName) || !testCaseName.contains("_GetCredential")) {
			return super.postRequestWithCookieAuthHeaderAndXsrfToken(url, jsonInput, cookieName, testCaseName);
		}
		JSONObject body = new JSONObject(jsonInput);
		String accessToken = body.getString("idpAccessToken");
		body.remove("idpAccessToken");
		body.remove("client_id");
		Map<String, String> headers = new HashMap<>();
		headers.put("Authorization", "DPoP " + accessToken);
		headers.put("DPoP", dpopProof(url, accessToken, null));
		String payload = body.toString();
		GlobalMethods.reportRequest(headers.toString(), payload, url);
		Response response = RestClient.postRequestWithMultipleHeadersWithoutCookie(url, payload,
				MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON, headers);
		GlobalMethods.checkXSSProtectionHeader(response, url);
		GlobalMethods.reportResponse(response.getHeaders().asList().toString(), url, response);
		return response;
	}

	private static boolean isDpopCase(String testCaseName) {
		return testCaseName != null && testCaseName.contains(DPOP_CASE_MARKER);
	}

	private static boolean isUseDpop() {
		return "true".equalsIgnoreCase(InjiCertifyConfigManager.getproperty("useDpop"));
	}

	private static Response postDpopForm(String url, Map<String, String> form, String nonce) {
		Map<String, String> headers = new HashMap<>();
		headers.put("DPoP", dpopProof(url, null, nonce));
		GlobalMethods.reportRequest(headers.toString(), form.toString(), url);
		return RestClient.postRequestWithFormDataBodyWithHeaders(url, form, headers);
	}

	private static Map<String, String> jsonToForm(String json) {
		JSONObject object = new JSONObject(json);
		Map<String, String> form = new HashMap<>();
		Iterator<String> keys = object.keys();
		while (keys.hasNext()) {
			String key = keys.next();
			form.put(key, String.valueOf(object.get(key)));
		}
		return form;
	}

	private static String dpopProof(String htu, String accessToken, String nonce) {
		try {
			RSAKey key = dpopWalletKey();
			JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().jwtID(UUID.randomUUID().toString())
					.issueTime(new Date()).claim("htm", "POST").claim("htu", htu);
			if (accessToken != null) {
				claims.claim("ath", Base64URL.encode(MessageDigest.getInstance("SHA-256")
						.digest(accessToken.getBytes(StandardCharsets.US_ASCII))).toString());
			}
			if (nonce != null && !nonce.isBlank()) {
				claims.claim("nonce", nonce);
			}
			SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
					.type(new JOSEObjectType("dpop+jwt")).jwk(key.toPublicJWK()).build(), claims.build());
			jwt.sign(new RSASSASigner(key));
			return jwt.serialize();
		} catch (Exception e) {
			throw new IllegalStateException("Failed to build DPoP proof", e);
		}
	}

	private static RSAKey dpopWalletKey() throws java.text.ParseException {
		if (dpopWalletKey == null) {
			dpopWalletKey = RSAKey.parse(generateUniqueOidcJwkKey(DPOP_WALLET_KEY));
		}
		return dpopWalletKey;
	}

	public static TestCaseDTO isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		currentTestCaseName = testCaseName;
		
		int indexof = testCaseName.indexOf("_");
		String modifiedTestCaseName = testCaseName.substring(indexof + 1);

		addTestCaseDetailsToMap(modifiedTestCaseName, testCaseDTO.getUniqueIdentifier());

		String uniqueId = testCaseDTO.getUniqueIdentifier();
		String uniqueIdTrimmed = uniqueId == null ? "" : uniqueId.trim();
		boolean inRunScope = !testCasesInRunScope.isEmpty()
				&& testCasesInRunScope.contains(uniqueIdTrimmed);
		boolean mdocvpMosipIdPrerequisite = isMdocvpMosipIdPrerequisite(testCaseDTO);

		if (!testCasesInRunScope.isEmpty() && !inRunScope && !mdocvpMosipIdPrerequisite) {
			throw new SkipException(GlobalConstants.NOT_IN_RUN_SCOPE_MESSAGE);
		}
		
		currentTestCaseName = testCaseName;
		
		//When the captcha is enabled we cannot execute the test case as we can not generate the captcha token
		if (isCaptchaEnabled() == true) {
			GlobalMethods.reportCaptchaStatus(GlobalConstants.CAPTCHA_ENABLED, true);
			throw new SkipException(GlobalConstants.CAPTCHA_ENABLED_MESSAGE);
		}

		if (InjiTestRunner.skipAll == true) {
			throw new SkipException(GlobalConstants.PRE_REQUISITE_FAILED_MESSAGE);
		}

		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}

		if (isDpopCase(testCaseName) && !isUseDpop()) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		String uc = trimLowerUseCase();

		if (uc.equals("mock")) {
			if (!testCaseName.toLowerCase().contains("mock")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialForMockIDA")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}

		}
		if (uc.equals("sunbird")) {
			if (!testCaseName.toLowerCase().contains("sunbird")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialSunBirdC")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
		}

		if (uc.equals("mosipid") && testCaseName.toLowerCase().contains("mosipid") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		if (uc.equals("landregistry")) {
			if (!testCaseName.toLowerCase().contains("landregistry")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialForLandRegistry")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
		}
		if (uc.equals("mdl")) {
			if (testCaseName.toLowerCase().contains("sunbird")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
			if (testCaseName.toLowerCase().contains("mdl") == false) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
		}
		if (uc.equals("mdocvp") && testCaseName.toLowerCase().contains("mdocvp") == false
				&& !isMdocvpMosipIdPrerequisite(testCaseDTO)) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (uc.equals("preauthcode") && testCaseName.toLowerCase().contains("preauthcode") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (uc.equals("credentialconfig") && testCaseName.toLowerCase().contains("credentialconfig") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (uc.equals("svgtemplate") && testCaseName.toLowerCase().contains("svgtemplate") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		if (testCaseDTO != null && testCaseDTO.getAdditionalDependencies() != null
				&& AdminTestUtil.generateDependency == true) {
			addAdditionalDependencies(testCaseDTO);
		}

		return testCaseDTO;
	}

	static boolean isMdocvpMosipIdPrerequisite(TestCaseDTO testCaseDTO) {
		if (testCaseDTO == null || !"mdocvp".equals(trimLowerUseCase())) {
			return false;
		}
		String uniqueIdentifier = testCaseDTO.getUniqueIdentifier();
		if (uniqueIdentifier == null || uniqueIdentifier.isBlank()) {
			return false;
		}
		return MDOCVP_MOSIP_ID_VCI_PREREQUISITE_IDS.contains(uniqueIdentifier.trim());
	}
	
	public static boolean isSignatureSupportedForTheTestCase(TestCaseDTO testCaseDTO) {
		boolean bReturn = true;
		JSONObject testInputJson = new JSONObject(testCaseDTO.getInput());

		// Extract the credentialType and signatureSupported from the test input
		String credentialType = testInputJson.optString("credentialType", null);
		String signatureSupported = testInputJson.optString("signatureSupported", null);

		if (credentialType != null && signatureSupported != null) {
			List<String> signingAlgorithms = proofSigningAlgorithmsMap.get(credentialType);

			if (signingAlgorithms != null) {
				// If signatureSupported is not in the signing algorithms list, skip the test
				if (!signingAlgorithms.contains(signatureSupported)) {
					bReturn = false;
				}
			}
		}

		return bReturn;
	}
	
	public static String signJWKForMockID(String clientId, String accessToken, String cNonce, RSAKey jwkKey, String testCaseName,
			String tempUrl) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		JWSSigner signer;
		String proofJWT = "";
		String typ = "openid4vci-proof+jwt";
		JWK jwkHeader = jwkKey.toPublicJWK();
		SignedJWT signedJWT = null;

		try {
			signer = new RSASSASigner(jwkKey);
			Date currentTime = new Date();

			// Create a Calendar instance to manipulate time
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);

			// Add one hour to the current time
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600)); // Adding one hour

			// Get the updated expiration time
			Date expirationTime = calendar.getTime();

			JWTClaimsSet claimsSet = null;
			String nonce = resolveCNonce(accessToken, cNonce);
			
			if (testCaseName.contains("_Invalid_C_nonce_"))
				nonce = "jwt_payload.c_nonce123";
			else if (testCaseName.contains("_Empty_C_nonce_"))
				nonce = "";
			else if (testCaseName.contains("_SpaceVal_C_nonce_"))
				nonce = "  ";
			else if (testCaseName.contains("_Exp_C_nonce_"))
				nonce = "aXPrnkX78dMgkbkkocu7AV";
			else if (testCaseName.contains("_Empty_Typ_"))
				typ = "";
			else if (testCaseName.contains("_SpaceVal_Typ_"))
				typ = "  ";
			else if (testCaseName.contains("_Invalid_Typ_"))
				typ = "openid4vci-123@proof+jwt";
			else if (testCaseName.contains("_Invalid_JwkHeader_"))
				jwkHeader = RSAKey.parse(JWKKeyUtil.getJWKKey(BINDINGJWK1)).toPublicJWK();
			else if (testCaseName.contains("_Invalid_Aud_"))
				tempUrl = "sdfaf";
			else if (testCaseName.contains("_Empty_Aud_"))
				tempUrl = "";
			else if (testCaseName.contains("_SpaceVal_Aud_"))
				tempUrl = "  ";
			else if (testCaseName.contains("_Invalid_Iss_"))
				clientId = "sdfdsg";
			else if (testCaseName.contains("_Invalid_Exp_"))
				idTokenExpirySecs = 0;

			claimsSet = new JWTClaimsSet.Builder().audience(tempUrl).claim("nonce", nonce).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();
			
			if (testCaseName.contains("_Missing_Typ_")) {
				signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwkHeader).build(), claimsSet);
			} else if (testCaseName.contains("_Missing_JwkHeader_")) {
				signedJWT = new SignedJWT(
						new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(typ)).build(), claimsSet);
			} else if (testCaseName.contains("_Sign_PS256_")) {
				jwkHeader = new RSAKey.Builder((RSAKey) jwkHeader).algorithm(JWSAlgorithm.PS256).build();
				signedJWT = new SignedJWT(
						new JWSHeader.Builder(JWSAlgorithm.PS256).type(new JOSEObjectType(typ)).jwk(jwkHeader).build(),
						claimsSet);
			} else {
				signedJWT = new SignedJWT(
						new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(typ)).jwk(jwkHeader).build(),
						claimsSet);
			}

			signedJWT.sign(signer);
			proofJWT = signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt to get credential: " + e.getMessage());
		}
		return proofJWT;
	}

	private static String resolveCNonce(String accessToken, String cNonceOverride) throws Exception {
		if (cNonceOverride != null && !cNonceOverride.isBlank()) {
			return cNonceOverride;
		}
		if (accessToken == null || accessToken.isBlank()) {
			throw new IllegalArgumentException("accessToken is required to resolve c_nonce");
		}
		String[] jwtParts = accessToken.split("\\.");
		if (jwtParts.length < 2) {
			throw new IllegalArgumentException("Invalid JWT: missing payload segment");
		}
		byte[] jwtPayloadBytes = Base64.getUrlDecoder().decode(jwtParts[1]);
		String jwtPayload = new String(jwtPayloadBytes, StandardCharsets.UTF_8);
		com.fasterxml.jackson.databind.JsonNode cNonceNode = new ObjectMapper().readTree(jwtPayload).get("c_nonce");
		if (cNonceNode == null || cNonceNode.isNull()) {
			throw new IllegalArgumentException("c_nonce claim missing from access token");
		}
		return cNonceNode.asText();
	}
	
	public static String generateP256DidKey(byte[] rawP256PublicKey) {
		// P-256 public keys in compressed format are 33 bytes
		if (rawP256PublicKey == null || rawP256PublicKey.length != 33) {
			throw new IllegalArgumentException(
					"Invalid P-256 public key: must be 33 bytes (compressed format)");
		}

	// Multicodec prefix for P-256 (0x8024) as expected by DIDkeysProofManager
		byte[] prefix = new byte[] { (byte) 0x80, (byte) 0x24 };

		byte[] combined = new byte[prefix.length + rawP256PublicKey.length];
		System.arraycopy(prefix, 0, combined, 0, prefix.length);
		System.arraycopy(rawP256PublicKey, 0, combined, prefix.length, rawP256PublicKey.length);

		return "did:key:z" + Base58.encode(combined);
	}
	
	/**
	 * Extract compressed raw P-256 public key from an EC JWK using Bouncy Castle
	 * for correct compression.
	 */
	private static byte[] extractRawP256PublicKey(ECKey ecJWK) throws Exception {
		ECPublicKey publicKey = ecJWK.toECPublicKey();

		// Use BouncyCastle EC curve for compression
		org.bouncycastle.jce.spec.ECParameterSpec ecSpec =
				org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
		org.bouncycastle.math.ec.ECCurve curve = ecSpec.getCurve();

		java.security.spec.ECPoint javaPoint = publicKey.getW();
		org.bouncycastle.math.ec.ECPoint bcPoint = curve.createPoint(
				javaPoint.getAffineX(),
				javaPoint.getAffineY()
		);

		// true = compressed format (33 bytes)
		return bcPoint.getEncoded(true);
	}
	public static String signES256JWT(String clientId, String accessToken, String cNonce, String testCaseName, String tempUrl) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));

		String proofJWT = "";
		SignedJWT signedJWT;
		JWSHeader header = null;
		ECKey signingKey;
		

		try {
			// Generate EC P-256 keypair
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
			keyGen.initialize(new ECGenParameterSpec("secp256r1"));
			KeyPair keyPair = keyGen.generateKeyPair();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

			if (testCaseName.contains("_Did_Key_Sign_")) {
				// Convert to ECKey
				ECKey ecJWK = new ECKey.Builder(Curve.P_256, publicKey)
						.privateKey(privateKey)
						.build();

				// Extract compressed P-256 public key
				byte[] compressedKey = extractRawP256PublicKey(ecJWK);

				// Generate DID:key
				String didKey = generateP256DidKey(compressedKey);
				if (testCaseName.contains("_Did_Key_Sign_invalid")) {
					didKey = "did:key:zINVALIDDIDKEYFORPROOFTEST";
				}

				// Build header with DID key
				header = new JWSHeader.Builder(JWSAlgorithm.ES256)
						.keyID(didKey)
						.type(new JOSEObjectType("openid4vci-proof+jwt"))
						.build();

				signingKey = new ECKey.Builder(Curve.P_256, publicKey)
						.privateKey(privateKey)
						.build();

			} else {
				signingKey = new ECKey.Builder(Curve.P_256, publicKey)
						.privateKey(privateKey)
						.keyID(UUID.randomUUID().toString())
						.build();

				header = new JWSHeader.Builder(JWSAlgorithm.ES256)
						.jwk(signingKey.toPublicJWK())
						.type(new JOSEObjectType("openid4vci-proof+jwt"))
						.build();
			}
		

			Date currentTime = new Date();

			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);
			calendar.add(Calendar.SECOND, idTokenExpirySecs);
			Date expirationTime = calendar.getTime();

			String nonce = resolveCNonce(accessToken, cNonce);

			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience(tempUrl).claim("nonce", nonce).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();

			signedJWT = new SignedJWT(header, claimsSet);
			JWSSigner signer = new ECDSASigner(signingKey);

			signedJWT.sign(signer);
			proofJWT = signedJWT.serialize();

		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt with ES256: " + e.getMessage());
		}

		return proofJWT;
	}
	
	public static String generateSecp256k1DidKey(byte[] rawSecp256k1PublicKey) {
		// secp256k1 compressed public keys are always 33 bytes (0x02/0x03 + 32-byte x coordinate)
		if (rawSecp256k1PublicKey == null || rawSecp256k1PublicKey.length != 33) {
			throw new IllegalArgumentException("Invalid secp256k1 public key: must be 33 bytes (compressed format)");
		}

		// Multicodec prefix for secp256k1 (0xE701)
		byte[] prefix = new byte[]{(byte) 0xE7, 0x01};

		byte[] combined = new byte[prefix.length + rawSecp256k1PublicKey.length];
		System.arraycopy(prefix, 0, combined, 0, prefix.length);
		System.arraycopy(rawSecp256k1PublicKey, 0, combined, prefix.length, rawSecp256k1PublicKey.length);

		return "did:key:z" + Base58.encode(combined);
	}

	public static String signES256KJWT(String clientId, String accessToken, String cNonce, String testCaseName, String tempUrl) {
		int idTokenExpirySecs = Integer.parseInt(
				getValueFromEsignetActuator(
						InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS
				)
		);

		JWSSigner signer;
		String proofJWT = "";
		SignedJWT signedJWT;
		JWSHeader header;

		try {
			// 🔑 Ensure BC is available
			if (Security.getProvider("BC") == null) {
				Security.addProvider(new BouncyCastleProvider());
			}
			// Generate secp256k1 key pair using BouncyCastle provider
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
			keyGen.initialize(new ECGenParameterSpec("secp256k1"));
			KeyPair keyPair = keyGen.generateKeyPair();

			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			// Nimbus ECKey
			ECKey ecJWK = new ECKey.Builder(Curve.SECP256K1, publicKey)
					.privateKey(privateKey)
					.keyID(UUID.randomUUID().toString())
					.build();

			if (testCaseName.contains("_Did_Key_Sign_")) {
				// Compress public key (33 bytes: 0x02/0x03 + X)
				byte[] compressedKey = compressSecp256k1PublicKey(publicKey);

				// Generate did:key
				String didKey = generateSecp256k1DidKey(compressedKey);
				if (testCaseName.contains("_Did_Key_Sign_invalid")) {
					didKey = "did:key:zINVALIDDIDKEYFORPROOFTEST";
				}

				header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
						.type(new JOSEObjectType("openid4vci-proof+jwt"))
						.keyID(didKey)
						.build();
			} else {
				header = new JWSHeader.Builder(JWSAlgorithm.ES256K)
						.type(new JOSEObjectType("openid4vci-proof+jwt"))
						.jwk(ecJWK.toPublicJWK())
						.build();
			}

			Date currentTime = new Date();

			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);
			calendar.add(Calendar.SECOND, idTokenExpirySecs);
			Date expirationTime = calendar.getTime();

			String nonce = resolveCNonce(accessToken, cNonce);

			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
					.audience(tempUrl)
					.claim("nonce", nonce)
					.issuer(clientId)
					.issueTime(currentTime)
					.expirationTime(expirationTime)
					.jwtID(UUID.randomUUID().toString())
					.build();

			signedJWT = new SignedJWT(header, claimsSet);
			signer = new ECDSASigner(privateKey);

			// ✅ Fix: pass actual Provider object
			signer.getJCAContext().setProvider(Security.getProvider("BC"));

			signedJWT.sign(signer);
			proofJWT = signedJWT.serialize();

		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt with ES256K: " + e.getMessage(), e);
		}

		return proofJWT;
	}

	/**
	 * Compress a secp256k1 public key into 33-byte format.
	 */
	private static byte[] compressSecp256k1PublicKey(ECPublicKey publicKey) {
		java.security.spec.ECPoint w = publicKey.getW();
		BigInteger x = w.getAffineX();
		BigInteger y = w.getAffineY();

		// Prefix 0x02 if y is even, 0x03 if odd
		byte prefix = (y.testBit(0)) ? (byte) 0x03 : (byte) 0x02;

		byte[] xBytes = x.toByteArray();
		if (xBytes.length > 32) {
			xBytes = Arrays.copyOfRange(xBytes, xBytes.length - 32, xBytes.length);
		} else if (xBytes.length < 32) {
			byte[] padded = new byte[32];
			System.arraycopy(xBytes, 0, padded, 32 - xBytes.length, xBytes.length);
			xBytes = padded;
		}

		byte[] compressed = new byte[33];
		compressed[0] = prefix;
		System.arraycopy(xBytes, 0, compressed, 1, 32);

		return compressed;
	}


	public static String generateEd25519DidKey(byte[] rawEd25519PublicKey) {
		// Ed25519 public keys are 32 bytes
		if (rawEd25519PublicKey == null || rawEd25519PublicKey.length != 32) {
			throw new IllegalArgumentException("Invalid Ed25519 public key: must be 32 bytes");
		}

		// Multicodec prefix for Ed25519 (0xED01)
		byte[] prefix = new byte[]{(byte) 0xED, 0x01};

		byte[] combined = new byte[prefix.length + rawEd25519PublicKey.length];
		System.arraycopy(prefix, 0, combined, 0, prefix.length);
		System.arraycopy(rawEd25519PublicKey, 0, combined, prefix.length, rawEd25519PublicKey.length);

		return "did:key:z" + Base58.encode(combined);
	}
	public static String signED25519JWT(String clientId, String accessToken, String cNonce, String testCaseName, String tempUrl) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		JWSSigner signer;
		String proofJWT = "";
		SignedJWT signedJWT = null;
		JWSHeader header = null;

		try {
			OctetKeyPair edJWK = new OctetKeyPairGenerator(Curve.Ed25519).generate();

			if(testCaseName.contains("_Did_Key_Sign_")) {
				
				byte[] rawPublicKey = edJWK.getX().decode();

				String didKey = generateEd25519DidKey(rawPublicKey);
				if (testCaseName.contains("_Did_Key_Sign_invalid")) {
					didKey = "did:key:zINVALIDDIDKEYFORPROOFTEST";
				}
				
				header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
						.type(new JOSEObjectType("openid4vci-proof+jwt")).keyID(didKey).build();
			}else {
				header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
						.type(new JOSEObjectType("openid4vci-proof+jwt")).jwk(edJWK.toPublicJWK()).build();
			}

			Date currentTime = new Date();

			// Create a Calendar instance to manipulate time
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);

			// Add one hour to the current time
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600)); // Adding one hour

			// Get the updated expiration time
			Date expirationTime = calendar.getTime();

			String nonce = resolveCNonce(accessToken, cNonce);
			JWTClaimsSet claimsSet = null;

			claimsSet = new JWTClaimsSet.Builder().audience(tempUrl).claim("nonce", nonce).issuer(clientId)
					.issueTime(currentTime).expirationTime(expirationTime).jwtID(UUID.randomUUID().toString()).build();

			signedJWT = new SignedJWT(header, claimsSet);
			signer = new Ed25519Signer(edJWK);

			signedJWT.sign(signer);
			proofJWT = signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt to get credential: " + e.getMessage());
		}
		return proofJWT;
	}

	static JWSHeader pdiHolderProofHeader(OctetKeyPair holderKey) {
		// Embedded jwk, no kid: same shape as $PROOF_JWT_ED25519$ that MOSIP ID already
		// accepts. kid+jwk together is rejected as PROOF_HEADER_AMBIGUOUS_KEY, and a
		// kid-only did:jwk is not accepted by every deployed MOSIP ID build.
		return new JWSHeader.Builder(JWSAlgorithm.EdDSA).type(new JOSEObjectType("openid4vci-proof+jwt"))
				.jwk(holderKey.toPublicJWK()).build();
	}

	public static String signED25519JWTWithHolderJwk(String clientId, String accessToken, String cNonce, String tempUrl,
			OctetKeyPair holderKey) {
		int idTokenExpirySecs = Integer
				.parseInt(getValueFromEsignetActuator(InjiCertifyConfigManager.getEsignetActuatorPropertySection(),
						GlobalConstants.MOSIP_ESIGNET_ID_TOKEN_EXPIRE_SECONDS));
		try {
			JWSHeader header = pdiHolderProofHeader(holderKey);
			Date currentTime = new Date();
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(currentTime);
			calendar.add(Calendar.HOUR_OF_DAY, (idTokenExpirySecs / 3600));
			Date expirationTime = calendar.getTime();
			String nonce = resolveCNonce(accessToken, cNonce);
			JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience(tempUrl).claim("nonce", nonce)
					.issuer(clientId).issueTime(currentTime).expirationTime(expirationTime)
					.jwtID(UUID.randomUUID().toString()).build();
			SignedJWT signedJWT = new SignedJWT(header, claimsSet);
			signedJWT.sign(new Ed25519Signer(holderKey));
			return signedJWT.serialize();
		} catch (Exception e) {
			logger.error("Exception while signing proof_jwt with holder JWK: " + e.getMessage());
			throw new RuntimeException("Failed to sign proof JWT with holder JWK", e);
		}
	}
	
	public static String generateFullNameForSunBirdR() {
		return faker.name().fullName();
	}

	public static String generateDobForSunBirdR() {
		Faker faker = new Faker();
		LocalDate dob = faker.date().birthday().toInstant().atZone(java.time.ZoneId.systemDefault()).toLocalDate();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		return dob.format(formatter);
	}
	
	public static JSONArray certifyActuatorResponseArray = null;
	private static final Map<String, JSONArray> certifyActuatorResponseByUrl = new HashMap<>();
	private static final String KYC_EXCHANGE_LOCALES_KEY = "mosip.certify.ida.kyc-exchange.accepted-locales";
	private static final String DEFAULT_MOSIPID_ACTUATOR_SECTION = "certify-mosipid";
	private static final String DEFAULT_MOSIPID_KYC_LOCALES = "en";

	public static String getValueFromCertifyActuator(String section, String key) {
		return getValueFromCertifyActuator(section, key, InjiCertifyConfigManager.getInjiCertifyBaseUrl());
	}

	public static String getValueFromCertifyActuator(String section, String key, String certifyBaseUrl) {
		if (certifyBaseUrl == null || certifyBaseUrl.isBlank() || key == null || key.isBlank()) {
			return null;
		}
		String actuatorPath = InjiCertifyConfigManager.getproperty("actuatorCertifyEndpoint");
		if (actuatorPath == null || actuatorPath.isBlank()) {
			actuatorPath = InjiCertifyConfigManager.getproperty("actuatorcertifyEndpoint");
		}
		if (actuatorPath == null || actuatorPath.isBlank()) {
			actuatorPath = "/v1/certify/actuator/env";
		}
		String url = certifyBaseUrl.replaceAll("/+$", "") + actuatorPath;
		String actuatorCacheKey = url + String.valueOf(section) + key;

		String value = actuatorValueCache.get(actuatorCacheKey);
		if (value != null) {
			return value;
		}

		try {
			JSONArray propertySources = certifyActuatorResponseByUrl.get(url);
			if (propertySources == null) {
				Response response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
				JSONObject responseJson = new JSONObject(response.getBody().asString());
				propertySources = responseJson.optJSONArray("propertySources");
				if (propertySources != null && propertySources.length() > 0) {
					certifyActuatorResponseByUrl.put(url, propertySources);
					if (certifyActuatorResponseArray == null) {
						certifyActuatorResponseArray = propertySources;
					}
				} else {
					propertySources = propertySources == null ? new JSONArray() : propertySources;
				}
			}

			value = findValueInCertifyActuatorSources(propertySources, section, key);
			if (value != null) {
				actuatorValueCache.put(actuatorCacheKey, value);
				logger.info("Actuator: " + url + " key: " + key + " value: " + value);
			} else {
				logger.warn("No value found for section: " + section + ", key: " + key + " url: " + url);
			}

			return value;
		} catch (JSONException e) {
			logger.error("JSON parsing error for section: " + section + ", key: " + key + " - " + e.getMessage());
			return null;
		} catch (Exception e) {
			logger.error("Error fetching value for section: " + section + ", key: " + key + " - " + e.getMessage());
			return null;
		}
	}

	static String resolveKycExchangeLocales(String testCaseName) {
		boolean mosipId = isMosipIdTestName(testCaseName);
		String certifyBaseUrl = mosipId ? getMosipIdCertifyBaseUrl()
				: InjiCertifyConfigManager.getInjiCertifyBaseUrl();
		String section = mosipId
				? firstNonBlank(InjiCertifyConfigManager.getproperty("mosipIdCertifyActuatorPropertySection"),
						DEFAULT_MOSIPID_ACTUATOR_SECTION)
				: InjiCertifyConfigManager.getproperty("certifyActuatorPropertySection");
		String locales = getValueFromCertifyActuator(section, KYC_EXCHANGE_LOCALES_KEY, certifyBaseUrl);
		if (locales != null && !locales.isBlank()) {
			return locales.trim();
		}
		if (mosipId) {
			String fallback = firstNonBlank(InjiCertifyConfigManager.getproperty("mosipIdKycExchangeLocales"),
					DEFAULT_MOSIPID_KYC_LOCALES);
			logger.warn("Mosip ID kyc-exchange locales missing from actuator; using fallback '" + fallback + "'");
			return fallback;
		}
		return locales;
	}

	static String findValueInCertifyActuatorSources(JSONArray propertySources, String section, String key) {
		if (propertySources == null || key == null || key.isBlank()) {
			return null;
		}
		String fromPreferredSection = readActuatorProperty(propertySources, key, section, true);
		if (fromPreferredSection != null && !fromPreferredSection.isBlank()) {
			return fromPreferredSection;
		}
		return readActuatorProperty(propertySources, key, section, false);
	}

	private static String readActuatorProperty(JSONArray propertySources, String key, String section,
			boolean requireSectionMatch) {
		if (requireSectionMatch && (section == null || section.isBlank())) {
			return null;
		}
		for (int i = 0, size = propertySources.length(); i < size; i++) {
			try {
				JSONObject eachJson = propertySources.getJSONObject(i);
				String name = eachJson.optString("name", "");
				if (requireSectionMatch && !name.contains(section)) {
					continue;
				}
				JSONObject properties = eachJson.optJSONObject(GlobalConstants.PROPERTIES);
				if (properties == null || !properties.has(key)) {
					continue;
				}
				String value = extractActuatorPropertyValue(properties.get(key));
				if (value != null && !value.isBlank()) {
					return value;
				}
			} catch (Exception e) {
				logger.warn("Skipping actuator property source at index " + i + ": " + e.getMessage());
			}
		}
		return null;
	}

	private static String extractActuatorPropertyValue(Object raw) {
		if (raw == null || raw == JSONObject.NULL) {
			return null;
		}
		if (raw instanceof JSONObject) {
			JSONObject rawObject = (JSONObject) raw;
			if (!rawObject.has(GlobalConstants.VALUE) || rawObject.isNull(GlobalConstants.VALUE)) {
				return null;
			}
			return String.valueOf(rawObject.get(GlobalConstants.VALUE));
		}
		return String.valueOf(raw);
	}
	
	public void updateCacheFromRow(Map<String, Object> row, String idKeyName, String testCaseName) {
		if (row == null || row.isEmpty() || idKeyName == null || idKeyName.trim().isEmpty()) {
			return;
		}

		String[] keys = idKeyName.split(",");
		for (String key : keys) {
			String trimmedKey = key.trim();
			if (!trimmedKey.isEmpty()) {
				if (row.containsKey(trimmedKey)) {
					Object value = row.get(trimmedKey);
					if (value != null) {
						writeAutoGeneratedId(testCaseName, trimmedKey, value.toString());
					} else {
						logger.error("Key '" + trimmedKey + "' has null value in DB row for testCase: " + testCaseName);
					}
				} else {
					logger.error("Key '" + trimmedKey + "' not found in DB row for testCase: " + testCaseName);
				}
			}
		}
	}
	
	public static String normalizeIndexedAttributes(String json) {
		try {
			
			json = fixBrokenJson(json);

			// read top-level JSON into a Map
			Map<String, Object> requestMap = mapper.readValue(json, Map.class);

			// Process only if key exists
			if (requestMap.containsKey(InjiCertifyConstants.INDEXED_ATTRIBUTES_EQUALS_STRING)) {
				Object raw = requestMap.get(InjiCertifyConstants.INDEXED_ATTRIBUTES_EQUALS_STRING);

				requestMap.put(InjiCertifyConstants.INDEXED_ATTRIBUTES_EQUALS_STRING, convertToMapIfJsonObject(raw));
			}

			// Convert back to JSON string
			return mapper.writeValueAsString(requestMap);

		} catch (Exception e) {
			throw new RuntimeException("Failed to normalize indexedAttributesEquals", e);
		}
	}

	private static Object convertToMapIfJsonObject(Object value) {
		try {
			if (value instanceof Map) {
				return value; // already a map
			} else if (value instanceof String) {
				String str = ((String) value).trim();
				if (str.startsWith("{") && str.endsWith("}")) {
					JsonNode node = mapper.readTree(str);
					if (node.isObject()) {
						// convert JSON object string into Map
						return mapper.readValue(str, Map.class);
					}
				}
			}
		} catch (Exception ignore) {
			// if parsing fails, just return the original value
		}
		return value;
	}
	
	public static String fixBrokenJson(String json) {
		// Look for "indexedAttributesEquals": "{"..."}"
		return json.replaceAll("\"indexedAttributesEquals\"\\s*:\\s*\"\\{", "\"indexedAttributesEquals\": {")
				.replaceAll("\\}\"\\s*(,?)", "}$1");
	}

	@Override
	protected void writeAutoGeneratedId(Response response, String idKeyName, String testCaseName) {
		super.writeAutoGeneratedId(response, idKeyName, testCaseName);
		persistOpenId4VpRequestFromIarResponse(response, testCaseName);
		cacheMosipIdentityVcFromCredentialResponse(response, testCaseName);
	}

	private void persistOpenId4VpRequestFromIarResponse(Response response, String testCaseName) {
		try {
			JSONObject jsonObject = new JSONObject(response.getBody().asString());
			if (!jsonObject.has("openid4vp_request")) {
				return;
			}
			JSONObject openId4VpRequest = jsonObject.getJSONObject("openid4vp_request");
			writeAutoGeneratedId(testCaseName, "openid4vp_request", openId4VpRequest.toString());
			logger.info("Saved openid4vp_request for test case: " + testCaseName);
		} catch (Exception e) {
			logger.error("Failed to persist openid4vp_request from IAR response: " + e.getMessage());
		}
	}

	private JSONObject resolveOpenId4VpRequest() {
		String cachedOpenId4VpRequest = replaceIdWithAutogeneratedId(
				"$ID:IAR_initial_Request_mdocvp_all_Valid_Smoke_sid_openid4vp_request$", "$ID:");
		if (cachedOpenId4VpRequest == null || cachedOpenId4VpRequest.isBlank()
				|| cachedOpenId4VpRequest.contains("$ID:")) {
			throw new RuntimeException(
					"openid4vp_request not found in cache. Ensure TC_InjiCertify_IARInitialRequest_01 ran successfully.");
		}
		return new JSONObject(cachedOpenId4VpRequest);
	}

	public static JSONObject loadJsonFromHbsTemplate(String inputTemplatePath) {
		String json = new InjiCertifyUtil().getJsonFromTemplate("{}", inputTemplatePath);
		return new JSONObject(json);
	}

	public static JSONObject getPresentationDuringIssuanceVpTestData(String key) {
		if ("sampleMosipIdentityVc".equals(key)) {
			return resolveSampleMosipIdentityVc();
		}
		JSONObject template = loadJsonFromHbsTemplate(
				"injicertify/PresentationDuringIssuance/GetCredential/GetCredential");
		return template.getJSONObject("vpTestData").getJSONObject(key);
	}

	public static void cacheMosipIdentityVcFromCredentialResponse(Response response, String testCaseName) {
		if (response == null || testCaseName == null || !testCaseName.contains("_mdocvp_holder")) {
			return;
		}
		try {
			JSONObject vc = extractMosipIdentityVcFromCredentialResponse(response.getBody().asString());
			autoGeneratedIDValueCache.put(SAMPLE_MOSIP_IDENTITY_VC_CACHE_KEY, vc.toString());
			logger.info("Cached Mosip identity VC from " + testCaseName + " for Presentation During Issuance VP");
		} catch (Exception e) {
			logger.error("Failed to cache Mosip identity VC from credential response: " + e.getMessage(), e);
		}
	}

	private static JSONObject resolveSampleMosipIdentityVc() {
		String cachedVc = autoGeneratedIDValueCache.get(SAMPLE_MOSIP_IDENTITY_VC_CACHE_KEY);
		if (cachedVc != null && !cachedVc.isBlank()) {
			logger.info("Reusing Mosip identity VC cached by GetCredential Mosip ID PDI prerequisite");
			return new JSONObject(cachedVc);
		}
		throw new SkipException(
				"Mosip identity VC is not cached. Ensure mdocvp Mosip ID prerequisites ran: "
						+ "AddIdentity, OIDC on eSignet, OAuthDetails, AuthenticateUser, AuthorizationCode, "
						+ "GenerateToken, GenerateNonce, and GetCredentialMosipID mdocvp holder "
						+ "(TC_injicertify_Mosipidcredentialissuance_pdi_01).");
	}

	private static JSONObject extractMosipIdentityVcFromCredentialResponse(String responseBody) {
		JSONObject responseJson = new JSONObject(responseBody);
		if (!responseJson.has("credentials")) {
			throw new RuntimeException("Mosip identity VC response does not contain credentials array");
		}
		JSONArray credentials = responseJson.getJSONArray("credentials");
		if (credentials.length() == 0) {
			throw new RuntimeException("Mosip identity VC response credentials array is empty");
		}
		JSONObject credentialEntry = credentials.getJSONObject(0);
		if (!credentialEntry.has("credential")) {
			throw new RuntimeException("Mosip identity VC response does not contain credential object");
		}
		return credentialEntry.getJSONObject("credential");
	}

	public static String serializeJson(Object jsonObject) {
		if (jsonObject == null) {
			return "{}";
		}
		return normalizeLiteralEqualsInJsonWire(jsonObject.toString());
	}

	public static String normalizeLiteralEqualsInJsonWire(String jsonWire) {
		if (jsonWire == null) {
			return null;
		}
		return jsonWire.replace("\\u003d", "=");
	}

	public static String buildMdocvpIarRequestWire(String authSession, String openId4VpResponseJson) {
		return buildMdocvpIarRequestWire(authSession, openId4VpResponseJson, null);
	}

	public static String buildMdocvpIarRequestWire(String authSession, String openId4VpResponseJson, String clientId) {
		JSONObject request = new JSONObject();
		request.put("auth_session", authSession);
		if (clientId != null && !clientId.isBlank()) {
			request.put("client_id", clientId);
		}
		request.put("openid4vp_response", openId4VpResponseJson);
		return serializeJson(request);
	}

	public static String formatMosipVcAsGetCredentialResponse(JSONObject vc) {
		JSONObject response = new JSONObject();
		response.put("credential", vc);
		return serializeJson(response);
	}
	
	protected void writeAutoGeneratedIdWithResponse(Response response, String idKeyName, String testCaseName) {
		JSONObject responseJson = null;
		try {
			// 🔹 Parse JSON safely (handles both JSONObject and JSONArray)
			Object parsedResponse = new JSONTokener(response.getBody().asString()).nextValue();
			JSONObject jsonObject = null;

			if (parsedResponse instanceof JSONArray) {
				JSONArray jsonArray = (JSONArray) parsedResponse;
				if (jsonArray.length() > 0) {
					jsonObject = jsonArray.getJSONObject(0); // take first object
				} else {
					logger.error("Empty JSON array in response");
					return;
				}
			} else if (parsedResponse instanceof JSONObject) {
				jsonObject = (JSONObject) parsedResponse;
			} else {
				logger.error("Unexpected JSON format: " + response.getBody().asString());
				return;
			}

			// 🔹 Decide which object to use based on testcase
			if (jsonObject.has(GlobalConstants.RESPONSE) && jsonObject.optJSONObject(GlobalConstants.RESPONSE) != null) {
				responseJson = jsonObject.getJSONObject(GlobalConstants.RESPONSE);
			} else {
				responseJson = jsonObject;
			}

			// 🔹 Extract all requested fields
			String[] fieldNames = idKeyName.split(",");
			for (String filedName : fieldNames) {
				String identifierKeyName = getAutogenIdKeyName(testCaseName, filedName);

				if (responseJson != null) {
					if (responseJson.has(filedName)) {
						autoGeneratedIDValueCache.put(identifierKeyName, responseJson.get(filedName).toString());
					} else {
						String keyValue = findClientId(responseJson.toString(), filedName);
						if (keyValue != null) {
							autoGeneratedIDValueCache.put(identifierKeyName, keyValue);
						}
					}

				} else {
					logger.error(GlobalConstants.ERROR_STRING_3 + filedName + GlobalConstants.WRITE_STRING
							+ response.asString());
				}
			}

		} catch (Exception e) {
			logger.error("Exception while getting autogenerated id and writing in property file:" + e.getMessage());
		}
	}
	
	private static final Pattern RAW_PLACEHOLDER = Pattern.compile("\"RAW:(\\$\\{[^}]+})\"");

	public static String unwrapRawPlaceholders(String json) {
		return RAW_PLACEHOLDER.matcher(json).replaceAll("$1");
	}

	public static String getIdFromCsvUrl(String url) {
		logger.info("Reading CSV from URL");

		try (BufferedReader reader = new BufferedReader(
				new InputStreamReader(URI.create(url).toURL().openStream(), StandardCharsets.UTF_8))) {

			String header = reader.readLine();
			logger.info("CSV Header");

			String line = reader.readLine();
			logger.info("CSV First Data Row");

			if (line == null || line.isBlank()) {
				logger.error("CSV does not contain data rows");
				return "";
			}

			int commaIndex = line.indexOf(',');

			if (commaIndex == -1) {
				logger.error("Invalid CSV format, comma not found");
				return "";
			}

			return line.substring(0, commaIndex).trim();

		} catch (Exception e) {
			logger.error("Exception while reading csv file", e);
		}

		return "";
	}
	
	public static String extractOfferIdFromCredeUri(String credeuri) {
		if (credeuri == null || credeuri.isEmpty()) {
			throw new SkipException("Marking testcase as skipped as required field is empty credential_offer_uri");
		}

		// ----- TRIM / EXTRACT offer_id ----- // Only take the last segment after "%2F"
		return credeuri.substring(credeuri.lastIndexOf("%2F") + 3);
	}

	public static void validateMdocCredentialResponse(Response response, String testCaseName) {
		String body = response.asString();
		JSONObject json;
		try {
			json = new JSONObject(body);
		} catch (JSONException e) {
			throw new RuntimeException("mDoc response is not valid JSON for " + testCaseName);
		}

		if (!json.has("credentials")) {
			throw new RuntimeException(
				"mDoc response missing 'credentials' array for " + testCaseName);
		}

		JSONArray credentials = json.getJSONArray("credentials");
		if (credentials.length() == 0) {
			throw new RuntimeException(
				"mDoc response 'credentials' array is empty for " + testCaseName);
		}

		JSONObject firstEntry = credentials.getJSONObject(0);
		if (!firstEntry.has("credential")) {
			throw new RuntimeException(
				"mDoc response first entry missing 'credential' field for " + testCaseName);
		}

		Object credentialField = firstEntry.get("credential");

		if (!(credentialField instanceof String)) {
			throw new RuntimeException(
				"mDoc 'credential' must be a base64url string per OpenID4VCI v1.0, but got type: "
				+ credentialField.getClass().getSimpleName()
				+ " for " + testCaseName);
		}

		String credentialStr = (String) credentialField;
		if (credentialStr.isBlank()) {
			throw new RuntimeException(
				"mDoc 'credential' field is blank for " + testCaseName);
		}

		try {
			byte[] decoded = Base64.getUrlDecoder().decode(credentialStr);
			if (decoded.length == 0) {
				throw new RuntimeException(
					"mDoc 'credential' base64url decodes to empty bytes for " + testCaseName);
			}
			logger.info(testCaseName + ": mDoc credential validated — base64url string, decoded size="
				+ decoded.length + " bytes");
		} catch (IllegalArgumentException e) {
			throw new RuntimeException(
				"mDoc 'credential' is not valid base64url for " + testCaseName);
		}
	}
	
}
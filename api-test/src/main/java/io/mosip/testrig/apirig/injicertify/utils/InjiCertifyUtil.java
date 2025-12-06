package io.mosip.testrig.apirig.injicertify.utils;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
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
import java.util.Map;
import java.util.UUID;
import java.util.Arrays;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bitcoinj.core.Base58;
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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
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

import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.injicertify.testrunner.MosipTestRunner;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.JWKKeyUtil;
import io.mosip.testrig.apirig.utils.KeyMgrUtility;
import io.mosip.testrig.apirig.utils.RestClient;
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
	
	public static void setLogLevel() {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}
	
	public static void configureOtp() {
		// For mock, mdoc and landregistry usecase also the OTP value is hard coded and not configurable.

		if (currentUseCase != null && !currentUseCase.isEmpty() && (currentUseCase.equals("mock")
				|| currentUseCase.equals("landregistry") || currentUseCase.equals("mdoc"))) {

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
		JSONObject vcTemplate = new JSONObject(requestJsonStr).getJSONObject("vcTemplate");
		return new JSONObject(requestJsonStr).put("vcTemplate", AdminTestUtil.encodeBase64(vcTemplate.toString()))
				.toString();
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
		JSONObject request = new JSONObject(inputJson);
		String emailId = null;
		String otp = null;

		if (request.has("otp")) {
			String challengeKey = request.getString("otp");
			if (challengeKey.endsWith(GlobalConstants.MOSIP_NET)
					|| challengeKey.endsWith(GlobalConstants.OTP_AS_PHONE)) {
				emailId = challengeKey;
				if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE)) {
					emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
					emailId = removeLeadingPlusSigns(emailId);
				}
				logger.info(emailId);
				otp = OTPListener.getOtp(emailId);
				request.put("otp", otp);
				inputJson = request.toString();
				return inputJson;
			}
		} else if (request.has(GlobalConstants.REQUEST)) {
			if (request.getJSONObject(GlobalConstants.REQUEST).has("otp")) {
				String challengeKey = request.getJSONObject(GlobalConstants.REQUEST).getString("otp");
				if (challengeKey.endsWith(GlobalConstants.MOSIP_NET)
						|| challengeKey.endsWith(GlobalConstants.OTP_AS_PHONE)) {
					emailId = challengeKey;
					if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE)) {
						emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
						emailId = removeLeadingPlusSigns(emailId);
					}
					logger.info(emailId);
					otp = OTPListener.getOtp(emailId);
					request.getJSONObject(GlobalConstants.REQUEST).put("otp", otp);
					inputJson = request.toString();
					return inputJson;
				}
			} else if (request.getJSONObject(GlobalConstants.REQUEST).has(GlobalConstants.CHALLENGELIST)) {
				if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
						.length() > 0) {
					if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
							.getJSONObject(0).has(GlobalConstants.CHALLENGE)) {

						String challengeKey = request.getJSONObject(GlobalConstants.REQUEST)
								.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
								.getString(GlobalConstants.CHALLENGE);

						if (challengeKey.endsWith(GlobalConstants.MOSIP_NET)
								|| challengeKey.endsWith(GlobalConstants.OTP_AS_PHONE)) {
							emailId = challengeKey;
							if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE)) {
								emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
								emailId = removeLeadingPlusSigns(emailId);
							}
							logger.info(emailId);
							otp = OTPListener.getOtp(emailId);
							request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
									.getJSONObject(0).put(GlobalConstants.CHALLENGE, otp);
							inputJson = request.toString();
						}
					}
				}
			}
			return inputJson;
		}

		return inputJson;
	}
	
	protected static final String OIDCJWK1 = "oidcJWK1";
	protected static final String OIDCJWK4 = "oidcJWK4";
	
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
	
	protected static final String BINDINGJWK1 = "bindingJWK1";

	public String inputStringKeyWordHandeler(String jsonString, String testCaseName) {
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
		
		if (jsonString.contains(GlobalConstants.TIMESTAMP)) {
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
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

		if (jsonString.contains("$OIDCJWKKEY$")) {
			String jwkKey = "";
			if (gettriggerESignetKeyGen1()) {
				jwkKey = JWKKeyUtil.generateAndCacheJWKKey(OIDCJWK1);
				settriggerESignetKeyGen1(false);
			} else {
				jwkKey = JWKKeyUtil.getJWKKey(OIDCJWK1);
			}
			jsonString = replaceKeywordValue(jsonString, "$OIDCJWKKEY$", jwkKey);
		}
		
		if (jsonString.contains("$PROOF_JWT$")) {
			JWKKeyUtil.generateAndCacheJWKKey(BINDINGJWK1);
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK1);
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
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT$",
					signJWKForMockID(clientId, accessToken, oidcJWKKey1, testCaseName, tempUrl));
		}		

		if (jsonString.contains("$OIDCJWKKEY4$")) {
			String jwkKey = "";
			if (gettriggerESignetKeyGen13()) {
				jwkKey = JWKKeyUtil.generateAndCacheJWKKey(OIDCJWK4);
				settriggerESignetKeyGen13(false);
			} else {
				jwkKey = JWKKeyUtil.getJWKKey(OIDCJWK4);
			}
			jsonString = replaceKeywordValue(jsonString, "$OIDCJWKKEY4$", jwkKey);
		}
		if (jsonString.contains("$PROOF_JWT_3$")) {
			JWKKeyUtil.generateAndCacheJWKKey(BINDINGJWK1);
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK4);
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
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_3$",
					signJWKForMockID(clientId, accessToken, oidcJWKKey4, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("$PROOF_JWT_ED25519$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ED25519$",
					signED25519JWT(clientId, accessToken, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("$PROOF_JWT_ES256$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ES256$",
					signES256JWT(clientId, accessToken, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("$PROOF_JWT_ES256K$")) {
			JSONObject request = new JSONObject(jsonString);
			String clientId = "";
			String accessToken = "";
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();
			tempUrl = getBaseURL(testCaseName, InjiCertifyConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_ES256K$",
					signES256KJWT(clientId, accessToken, testCaseName, tempUrl));
		}

		if (jsonString.contains("$CLIENT_ASSERTION_JWT$")) {
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK1);
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
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK4);
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

		if (jsonString.contains("$CLIENT_ASSERTION_USER4_JWK$")) {
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK4);
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
			String oidcJWKKeyString = JWKKeyUtil.getJWKKey(OIDCJWK4);
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
			String tempUrl = "";
			if (request.has("client_id")) {
				clientId = request.getString("client_id");
				request.remove("client_id");
			}
			if (request.has("idpAccessToken")) {
				accessToken = request.getString("idpAccessToken");
			}
			jsonString = request.toString();

			String baseURL = InjiCertifyConfigManager.getInjiCertifyBaseUrl();
			if (testCaseName.contains("_GetCredentialSunBirdC")) {
				tempUrl = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
			}
			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_2$",
					signJWKForMockID(clientId, accessToken, oidcJWKKey4, testCaseName, tempUrl));
		}
		
		if (jsonString.contains("indexedAttributesEquals")) {
			jsonString = normalizeIndexedAttributes(jsonString);
		}

		return jsonString;
	}
	
	private static final String CA_P12_FILE_NAME = "-ca.p12"; 
	private static int rpPartnerCertExpiryYears = 5;
	protected String signCsrAndGenerateCert(String organization, String csr, String algorithm, String filePrepend)
			throws OperatorCreationException, CertificateException, IOException, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableEntryException {
		KeyMgrUtility keyMgrUtility = new KeyMgrUtility();

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
	
	public static String getJsonFromInjiCertifyWellKnownEndPoint() {
		String url = InjiCertifyConfigManager.getInjiCertifyBaseUrl()
				+ InjiCertifyConfigManager.getproperty("injiCertifyWellKnownEndPoint");

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

		if (testCaseName.contains("_GetCredentialSunBirdC")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GetCredentialMosipID")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GenerateTokenVCIMOSIPID")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GenerateToken_ForMockIDA")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GenerateToken_ForLandRegistry")|| testCaseName.contains("_GenerateToken_FormDoc")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GetCredentialForMockIDA")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer", baseURL);
		} else if (testCaseName.contains("_GetCredentialForLandRegistry")|| testCaseName.contains("_GetCredentialFormDoc")) {
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
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOSIPIDBASEURL$")) {
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return InjiCertifyConfigManager.getEsignetBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
				&& testCaseName.contains("GetCredentialSunBirdC")) {
			return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
					&& testCaseName.contains("CredentialConfig")) {
				return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOSIPIDBASEURL$")
				&& testCaseName.contains("_GetCredentialMosipID")) {
			return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOCKIDABASEURL$")
				&& testCaseName.contains("_GetCredentialForMockIDA")) {
			return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$SUNBIRDBASEURL$")
				&& testCaseName.contains("Policy_")) {
			return InjiCertifyConfigManager.getSunBirdBaseURL();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYBASEURL$")) {
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
	
	public static TestCaseDTO isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		currentTestCaseName = testCaseName;
		
		int indexof = testCaseName.indexOf("_");
		String modifiedTestCaseName = testCaseName.substring(indexof + 1);

		addTestCaseDetailsToMap(modifiedTestCaseName, testCaseDTO.getUniqueIdentifier());
		
		if (!testCasesInRunScope.isEmpty()
				&& testCasesInRunScope.contains(testCaseDTO.getUniqueIdentifier()) == false) {
			throw new SkipException(GlobalConstants.NOT_IN_RUN_SCOPE_MESSAGE);
		}
		
		currentTestCaseName = testCaseName;
		
		//When the captcha is enabled we cannot execute the test case as we can not generate the captcha token
		if (isCaptchaEnabled() == true) {
			GlobalMethods.reportCaptchaStatus(GlobalConstants.CAPTCHA_ENABLED, true);
			throw new SkipException(GlobalConstants.CAPTCHA_ENABLED_MESSAGE);
		}

		if (MosipTestRunner.skipAll == true) {
			throw new SkipException(GlobalConstants.PRE_REQUISITE_FAILED_MESSAGE);
		}

		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}

		if (currentUseCase.equalsIgnoreCase("mock")) {
			if (!testCaseName.toLowerCase().contains("mock")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialForMockIDA")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}

		}
		if (currentUseCase.toLowerCase().equals("sunbird")) {
			if (!testCaseName.toLowerCase().contains("sunbird")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialSunBirdC")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
		}

		if (currentUseCase.toLowerCase().equals("mosipid") && testCaseName.toLowerCase().contains("mosipid") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		if (currentUseCase.equalsIgnoreCase("landregistry")) {
			if (!testCaseName.toLowerCase().contains("landregistry")) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			} else if (testCaseName.contains("_GetCredentialForLandRegistry")
					&& !(isSignatureSupportedForTheTestCase(testCaseDTO))) {
				throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
			}
		}
		if (currentUseCase.toLowerCase().equals("mdoc") && testCaseName.toLowerCase().contains("mdoc") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (currentUseCase.toLowerCase().equals("credentialconfig") && testCaseName.toLowerCase().contains("credentialconfig") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (currentUseCase.toLowerCase().equals("svgtemplate") && testCaseName.toLowerCase().contains("svgtemplate") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		
		// Handle extra workflow dependencies
		if (testCaseDTO != null && testCaseDTO.getAdditionalDependencies() != null
				&& AdminTestUtil.generateDependency == true) {
			addAdditionalDependencies(testCaseDTO);
		}

		return testCaseDTO;
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
	
	public static String signJWKForMockID(String clientId, String accessToken, RSAKey jwkKey, String testCaseName,
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
	public static String signES256JWT(String clientId, String accessToken, String testCaseName, String tempUrl) {
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

			signedJWT = SignedJWT.parse(accessToken);
			String nonce = signedJWT.getJWTClaimsSet().getClaim("c_nonce").toString();

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

	public static String signES256KJWT(String clientId, String accessToken, String testCaseName, String tempUrl) {
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

	        signedJWT = SignedJWT.parse(accessToken);
	        String nonce = signedJWT.getJWTClaimsSet().getClaim("c_nonce").toString();

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
	public static String signED25519JWT(String clientId, String accessToken, String testCaseName, String tempUrl) {
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
				
				header = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
						.type(new JOSEObjectType("openid4vci-proof+jwt")).keyID(didKey).build();
			}else {
				header = new JWSHeader.Builder(JWSAlgorithm.Ed25519)
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

			signedJWT = SignedJWT.parse(accessToken);

			String nonce = signedJWT.getJWTClaimsSet().getClaim("c_nonce").toString();
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
	
	public static String getValueFromCertifyActuator(String section, String key, String url) {
		// Combine the cache key to uniquely identify each request
		String actuatorCacheKey = url + section + key;

		// Check if the value is already cached
		String value = actuatorValueCache.get(actuatorCacheKey);
		if (value != null) {
			return value; // Return cached value if available
		}

		try {
			// Fetch the actuator response array if it's not already populated
			if (certifyActuatorResponseArray == null) {
				Response response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
				JSONObject responseJson = new JSONObject(response.getBody().asString());
				certifyActuatorResponseArray = responseJson.getJSONArray("propertySources");
			}

			// Loop through the "propertySources" to find the matching section and key
			for (int i = 0, size = certifyActuatorResponseArray.length(); i < size; i++) {
				JSONObject eachJson = certifyActuatorResponseArray.getJSONObject(i);
				// Check if the section matches
				if (eachJson.get("name").toString().contains(section)) {
					// Get the value from the properties object
					JSONObject properties = eachJson.getJSONObject(GlobalConstants.PROPERTIES);
					if (properties.has(key)) {
						value = properties.getJSONObject(key).get(GlobalConstants.VALUE).toString();
						// Log the value if debug is enabled
						if (InjiCertifyConfigManager.IsDebugEnabled()) {
							logger.info("Actuator: " + url + " key: " + key + " value: " + value);
						}
						break; // Exit the loop once the value is found
					} else {
						logger.warn("Key '" + key + "' not found in section '" + section + "'.");
					}
				}
			}

			// Cache the retrieved value for future lookups
			if (value != null) {
				actuatorValueCache.put(actuatorCacheKey, value);
			} else {
				logger.warn("No value found for section: " + section + ", key: " + key);
			}

			return value;
		} catch (JSONException e) {
			// Handle JSON parsing exceptions separately
			logger.error("JSON parsing error for section: " + section + ", key: " + key + " - " + e.getMessage());
			return null; // Return null if JSON parsing fails
		} catch (Exception e) {
			// Catch any other exceptions (e.g., network issues)
			logger.error("Error fetching value for section: " + section + ", key: " + key + " - " + e.getMessage());
			return null; // Return null if any other exception occurs
		}
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
			if (jsonObject.has(GlobalConstants.RESPONSE)) {
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
	
}
package io.mosip.testrig.apirig.injicertify.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import javax.ws.rs.core.MediaType;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.testng.SkipException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.injicertify.testrunner.MosipTestRunner;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.ConfigManager;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.JWKKeyUtil;
import io.mosip.testrig.apirig.utils.RestClient;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;
import io.restassured.response.Response;

public class InjiCertifyUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(InjiCertifyUtil.class);
	public static String currentUseCase = "";
	
	public static void setLogLevel() {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
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

	public static String inputStringKeyWordHandeler(String jsonString, String testCaseName) {
		if (jsonString.contains("$ID:")) {
			String autoGenIdFileName = injiCertifyAutoGeneratedIdPropFileName;
			jsonString = replaceIdWithAutogeneratedId(jsonString, "$ID:", autoGenIdFileName);
		}
		
		if (jsonString.contains(GlobalConstants.TIMESTAMP)) {
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
		}

		if (jsonString.contains("$POLICYNUMBERFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$POLICYNUMBERFORSUNBIRDRC$",
					properties.getProperty("policyNumberForSunBirdRC"));
		}

		if (jsonString.contains("$FULLNAMEFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$FULLNAMEFORSUNBIRDRC$", fullNameForSunBirdRC);
		}

		if (jsonString.contains("$DOBFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$DOBFORSUNBIRDRC$", dobForSunBirdRC);
		}

		if (jsonString.contains("$CHALLENGEVALUEFORSUNBIRDC$")) {

			HashMap<String, String> mapForChallenge = new HashMap<String, String>();
			mapForChallenge.put(GlobalConstants.FULLNAME, fullNameForSunBirdRC);
			mapForChallenge.put(GlobalConstants.DOB, dobForSunBirdRC);

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
				tempUrl = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
						baseURL.replace("injicertify.", "injicertify-insurance."));
			}
			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_2$",
					signJWKForMockID(clientId, accessToken, oidcJWKKey4, testCaseName, tempUrl));
		}

		return jsonString;
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
	
	public static JSONArray esignetActuatorResponseArray = null;

	public static String getValueFromEsignetActuator(String section, String key) {
		String url = InjiCertifyConfigManager.getEsignetBaseUrl() + InjiCertifyConfigManager.getproperty("actuatorEsignetEndpoint");
		String actuatorCacheKey = url + section + key;
		String value = actuatorValueCache.get(actuatorCacheKey);
		if (value != null && !value.isEmpty())
			return value;

		try {
			if (esignetActuatorResponseArray == null) {
				Response response = null;
				JSONObject responseJson = null;
				response = RestClient.getRequest(url, MediaType.APPLICATION_JSON, MediaType.APPLICATION_JSON);
				responseJson = new JSONObject(response.getBody().asString());
				esignetActuatorResponseArray = responseJson.getJSONArray("propertySources");
			}

			for (int i = 0, size = esignetActuatorResponseArray.length(); i < size; i++) {
				JSONObject eachJson = esignetActuatorResponseArray.getJSONObject(i);
				if (eachJson.get("name").toString().contains(section)) {
					value = eachJson.getJSONObject(GlobalConstants.PROPERTIES).getJSONObject(key)
							.get(GlobalConstants.VALUE).toString();
					if (InjiCertifyConfigManager.IsDebugEnabled())
						logger.info("Actuator: " + url + " key: " + key + " value: " + value);
					break;
				}
			}
			actuatorValueCache.put(actuatorCacheKey, value);

			return value;
		} catch (Exception e) {
			logger.error(GlobalConstants.EXCEPTION_STRING_2 + e);
			return value;
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
					.issueTime(currentTime).expirationTime(expirationTime).build();

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
					.issueTime(currentTime).expirationTime(expirationTime).build();
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
					.issueTime(currentTime).expirationTime(expirationTime).build();

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
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint", InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GenerateToken_ForMockIDA")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint", InjiCertifyConfigManager.getEsignetBaseUrl());
		} else if (testCaseName.contains("_GetCredentialForMockIDA")) {
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
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOSIPIDBASEURL$")
				&& testCaseName.contains("_GetCredentialMosipID")) {
			return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOCKIDABASEURL$")
				&& testCaseName.contains("_GetCredentialForMockIDA")) {
			return InjiCertifyConfigManager. getInjiCertifyBaseUrl();
		} else if (testCaseDTO.getEndPoint().startsWith("$SUNBIRDBASEURL$")
				&& testCaseName.contains("Policy_")) {
			return InjiCertifyConfigManager.getSunBirdBaseURL();
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
		
		return "";
	}
	
	public static String isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();

		if (MosipTestRunner.skipAll == true) {
			throw new SkipException(GlobalConstants.PRE_REQUISITE_FAILED_MESSAGE);
		}

		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}

		if (currentUseCase.toLowerCase().equals("mock") && testCaseName.toLowerCase().contains("mock") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (currentUseCase.toLowerCase().equals("sunbird") && testCaseName.toLowerCase().contains("sunbird") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		if (currentUseCase.toLowerCase().equals("mosipid") && testCaseName.toLowerCase().contains("mosipid") == false) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}

		return testCaseName;
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
					.issueTime(currentTime).expirationTime(expirationTime).build();
			
			if (testCaseName.contains("_Missing_Typ_")) {
				signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwkHeader).build(), claimsSet);
			} else if (testCaseName.contains("_Missing_JwkHeader_")) {
				signedJWT = new SignedJWT(
						new JWSHeader.Builder(JWSAlgorithm.RS256).type(new JOSEObjectType(typ)).build(), claimsSet);
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
	
}

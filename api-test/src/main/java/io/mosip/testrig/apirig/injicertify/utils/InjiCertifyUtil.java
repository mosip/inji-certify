package io.mosip.testrig.apirig.injicertify.utils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

import org.apache.log4j.Logger;
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

import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.injicertify.testrunner.MosipTestRunner;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.ConfigManager;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.JWKKeyUtil;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;

public class InjiCertifyUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(InjiCertifyUtil.class);
	public static String currentUseCase = "";

	public static String smtpOtpHandler(String inputJson, TestCaseDTO testCaseDTO) {
		JSONObject request = new JSONObject(inputJson);
		String emailId = null;
		String otp = null;

		if (request.has("otp")) {
			String challengeKey = request.getString("otp");
			if (challengeKey.endsWith(GlobalConstants.MOSIP_NET)
					|| challengeKey.endsWith(GlobalConstants.OTP_AS_PHONE)) {
				emailId = challengeKey;
				if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE))
					emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
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
					if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE))
						emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
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
							if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE))
								emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
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

	public static String reqJsonKeyWordHandeler(String jsonString, String testCaseName) {
		
		if (jsonString.contains("$PROOF_JWT_FOR_INSURANCE$")) {
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

			if (BaseTestCase.currentModule.equals(GlobalConstants.INJICERTIFY)) {
				String baseURL = ConfigManager.getInjiCertifyBaseUrl();
				if (testCaseName.contains("_GetCredentialSunBirdC")) {
					tempUrl = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
							baseURL.replace("injicertify.", "injicertify-insurance."));
				}
			}
			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_FOR_INSURANCE$",
					signJWKForMockID(clientId, accessToken, oidcJWKKey4, testCaseName, tempUrl));
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

		return jsonString;
	}
	
	public static String replaceKeywordValue(String jsonString, String keyword, String value) {
		if (value != null && !value.isEmpty())
			return jsonString.replace(keyword, value);
		else
			throw new SkipException("Marking testcase as skipped as required fields are empty " + keyword);
	}
	
	public static String getBaseURL(String testCaseName, String baseURL) {
		String tempURL = "";

		if (testCaseName.contains("_GetCredentialSunBirdC")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
					baseURL.replace("injicertify.", "injicertify-insurance."));
		} else if (testCaseName.contains("_GetCredentialMosipID")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
					baseURL.replace("injicertify.", "injicertify-mosipid."));
		} else if (testCaseName.contains("_GenerateTokenVCIMOSIPID")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					baseURL.replace("injicertify.", "esignet-mosipid."));
		} else if (testCaseName.contains("_GenerateToken_ForMockIDA")) {
			tempURL = getValueFromEsignetWellKnownEndPoint("token_endpoint",
					baseURL.replace("injicertify.", "esignet-mock."));
		} else if (testCaseName.contains("_GetCredentialForMockIDA")) {
			tempURL = getValueFromInjiCertifyWellKnownEndPoint("credential_issuer",
					baseURL.replace("injicertify.", "injicertify-mock."));
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
			if (InjiCertifyConfigManager.getEsignetMockBaseURL() != null && !InjiCertifyConfigManager.getEsignetMockBaseURL().isBlank())
				return ApplnURI.replace("api-internal.", InjiCertifyConfigManager.getEsignetMockBaseURL());
		} else if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOSIPIDBASEURL$")) {
			return ApplnURI.replace("api-internal", "esignet-mosipid");
		} else if (testCaseDTO.getEndPoint().startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return ApplnURI.replace("api-internal", "esignet-mock");
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOSIPIDBASEURL$")) {
			return ApplnURI.replace("api-internal", "esignet-mosipid");
		} else if (endPoint != null && endPoint.startsWith("$ESIGNETMOCKIDABASEURL$")) {
			return ApplnURI.replace("api-internal", "esignet-mock");
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYINSURANCEBASEURL$")
				&& testCaseName.contains("GetCredentialSunBirdC")) {
			return ApplnURI.replace("api-internal", "injicertify-insurance");
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOSIPIDBASEURL$")
				&& testCaseName.contains("_GetCredentialMosipID")) {
			return ApplnURI.replace("api-internal", "injicertify-mosipid");
		} else if (testCaseDTO.getEndPoint().startsWith("$INJICERTIFYMOCKIDABASEURL$")
				&& testCaseName.contains("_GetCredentialForMockIDA")) {
			return ApplnURI.replace("api-internal", "injicertify-mock");
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
	
	public static String inputstringKeyWordHandeler(String jsonString, String testCaseName) {
		if (jsonString.contains(GlobalConstants.TIMESTAMP))
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
		
		
		return jsonString;
		
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
				.parseInt(getValueFromEsignetActuator(ConfigManager.getEsignetActuatorPropertySection(),
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
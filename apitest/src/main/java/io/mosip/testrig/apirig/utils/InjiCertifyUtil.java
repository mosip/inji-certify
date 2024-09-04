package io.mosip.testrig.apirig.utils;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.SkipException;

import com.nimbusds.jose.jwk.RSAKey;

import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.MockSMTPListener;

public class InjiCertifyUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(InjiCertifyUtil.class);

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
				otp = MockSMTPListener.getOtp(emailId);
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
					otp = MockSMTPListener.getOtp(emailId);
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
							otp = MockSMTPListener.getOtp(emailId);
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
		if (jsonString.contains("$PROOF_JWT_3$")) {
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
			tempUrl = getBaseURL(testCaseName, ConfigManager.getInjiCertifyBaseUrl());

			jsonString = replaceKeywordValue(jsonString, "$PROOF_JWT_3$",
					signJWKForMock(clientId, accessToken, oidcJWKKey4, testCaseName, tempUrl));
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
			String tempUrl = getBaseURL(testCaseName, ConfigManager.getInjiCertifyBaseUrl());
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
			String tempUrl = getBaseURL(testCaseName, ConfigManager.getInjiCertifyBaseUrl());
			
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
			if (ConfigManager.isInServiceNotDeployedList("sunbirdrc"))
				throw new SkipException(GlobalConstants.SERVICE_NOT_DEPLOYED_MESSAGE);
			if (ConfigManager.getEsignetMockBaseURL() != null && !ConfigManager.getEsignetMockBaseURL().isBlank())
				return ApplnURI.replace("api-internal.", ConfigManager.getEsignetMockBaseURL());
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
		
		return "";
	}
	
}
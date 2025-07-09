package io.mosip.testrig.apirig.injicertify.utils;

import io.mosip.testrig.apirig.utils.GlobalConstants;

public class InjiCertifyConstants extends GlobalConstants {
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE = "KBI";
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE_STRING = "sunbirdInsuranceAuthFactorType";
	
    public static final String USE_PRE_CONFIGURED_OTP_STRING = "usePreConfiguredOtp";
	
	public static final String PRE_CONFIGURED_OTP_STRING = "preconfiguredOtp";
	
	public static final String TRUE_STRING = "true";
	
	public static final String ALL_ONE_OTP_STRING = "111111";
	
	public static final String POSTGRES_LANDREGISTRY_PROPERTIES_STRING  = "postgres-landregistry.properties";
	
	public static final String CERTIFY_DEFAULT_PROPERTIES_STRING  = "certify-default.properties";
	
	public static final String INJICERTIFY_BASE_URL = InjiCertifyConfigManager.getInjiCertifyBaseUrl();
	
	public static final String INJICERTIFY_ACTUATOR_URL = INJICERTIFY_BASE_URL
			+ InjiCertifyConfigManager.getproperty("actuatorcertifyEndpoint");

	public static final String INJICERTIFY_ACTUATOR_PROPERTY = InjiCertifyConfigManager.getproperty("certifyActuatorPropertySection");	

}
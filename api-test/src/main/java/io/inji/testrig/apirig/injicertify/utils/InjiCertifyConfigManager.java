package io.inji.testrig.apirig.injicertify.utils;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import io.inji.testrig.apirig.injicertify.testrunner.InjiTestRunner;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.utils.ConfigManager;

public class InjiCertifyConfigManager extends ConfigManager{
	private static final Logger LOGGER = Logger.getLogger(InjiCertifyConfigManager.class);

	public static void init() {
		Logger configManagerLogger = Logger.getLogger(ConfigManager.class);
		configManagerLogger.setLevel(Level.WARN);
		
		Map<String, Object> moduleSpecificPropertiesMap = new HashMap<>();
		// Load scope specific properties
		try {
			String path = InjiTestRunner.getGlobalResourcePath() + "/config/injiCertify.properties";
			Properties props = getproperties(path);
			// Convert Properties to Map and add to moduleSpecificPropertiesMap
			for (String key : props.stringPropertyNames()) {
				moduleSpecificPropertiesMap.put(key, props.getProperty(key));
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
		// Add module specific properties as well.
		init(moduleSpecificPropertiesMap);
	}
	
	public static String getInjiCertifyDBURL() {
		return "jdbc:postgresql://" + getproperty("db-server") + ":" + getproperty("db-port") + "/" + getproperty("inji_certify_db_table");
	}

	public static String getInjiCertifyBaseUrl() {
		String configured = getproperty("injiCertifyBaseURL");
		if (!"mdocvp".equalsIgnoreCase(getproperty("useCaseToExecute"))) {
			return configured;
		}
		try {
			URI environmentUri = URI.create(BaseTestCase.ApplnURI);
			String host = environmentUri.getHost();
			if (host != null && host.startsWith("api-internal.")) {
				return environmentUri.getScheme() + "://injicertify-mdoc."
						+ host.substring("api-internal.".length());
			}
		} catch (RuntimeException e) {
			LOGGER.warn("Unable to derive the mdoc issuer URL from " + BaseTestCase.ApplnURI);
		}
		return configured;
	}

	public static void add(Map<String, Object> additionalPropertiesMap) {
		propertiesMap.putAll(additionalPropertiesMap);
	}

}
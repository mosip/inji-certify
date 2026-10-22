package io.inji.testrig.apirig.injicertify.testrunner;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.json.JSONObject;
import org.testng.TestNG;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import io.inji.testrig.apirig.injicertify.utils.InjiCertifyConfigManager;
import io.inji.testrig.apirig.injicertify.utils.InjiCertifyUtil;
import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.ExtractResource;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.AuthTestsUtil;
import io.mosip.testrig.apirig.utils.CertsUtil;
import io.mosip.testrig.apirig.utils.DependencyResolver;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.JWKKeyUtil;
import io.mosip.testrig.apirig.utils.KernelAuthentication;
import io.mosip.testrig.apirig.utils.KeyCloakUserAndAPIKeyGeneration;
import io.mosip.testrig.apirig.utils.KeycloakUserManager;
import io.mosip.testrig.apirig.utils.MispPartnerAndLicenseKeyGeneration;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.PartnerRegistration;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;

/**
 * Class to initiate inji api test execution
 * 
 * @author Vignesh
 *
 */
public class InjiTestRunner {
	private static final Logger LOGGER = Logger.getLogger(InjiTestRunner.class);
	private static String cachedPath = null;
	private static String generateDependency;

	public static String jarUrl = InjiTestRunner.class.getProtectionDomain().getCodeSource().getLocation().getPath();
	public static List<String> languageList = new ArrayList<>();
	public static boolean skipAll = false;
	private static String useCaseToExecute = "";

	/**
	 * C Main method to start mosip test execution
	 * 
	 * @param arg
	 */
	public static void main(String[] arg) {

		try {
			LOGGER.info("** ------------- API Test Rig Run Started --------------------------------------------- **");

			BaseTestCase.setRunContext(getRunType(), jarUrl);
			ExtractResource.removeOldMosipTestTestResource();
			if (getRunType().equalsIgnoreCase("JAR")) {
				ExtractResource.extractCommonResourceFromJar();
			} else {
				ExtractResource.copyCommonResources();
			}
			AdminTestUtil.init();
			InjiCertifyConfigManager.init();
			suiteSetup(getRunType());
			BaseTestCase.initializePMSDetails();
			SkipTestCaseHandler.loadTestcaseToBeSkippedList("testCaseSkippedList.txt");
			GlobalMethods.setModuleNameAndReCompilePattern(InjiCertifyConfigManager.getproperty("moduleNamePattern"));
			GlobalMethods.reportCaptchaStatus(GlobalConstants.CAPTCHA_ENABLED, false);
			setLogLevels();

			if ("true".equals(System.getenv("CI"))) {
				useCaseToExecute = "mock";
			} else {
				useCaseToExecute = InjiCertifyConfigManager.getproperty("useCaseToExecute");
				String envUseCase = System.getenv("ENV_USECASE");
				if (envUseCase != null && !envUseCase.isBlank()) {
					useCaseToExecute = envUseCase;
				}
				if (useCaseToExecute != null) {
					useCaseToExecute = useCaseToExecute.trim();
				} else {
					useCaseToExecute = "";
				}
			}

			if (!"true".equals(System.getenv("CI"))) {
				HealthChecker healthcheck = new HealthChecker();
				healthcheck.setCurrentRunningModule(GlobalConstants.INJICERTIFY);
				Thread trigger = new Thread(healthcheck);
				trigger.start();
			}

			if (!"true".equals(System.getenv("CI"))) {
				KeycloakUserManager.removeUser();
				KeycloakUserManager.createUsers();
				KeycloakUserManager.closeKeycloakInstance();
				AdminTestUtil.getRequiredField();
			}

			if (!"true".equals(System.getenv("CI"))) {
				BaseTestCase.getLanguageList();
				InjiCertifyUtil.configureOtp();
			}
			InjiCertifyUtil.getSupportedCredentialSigningAlg();

			generateDependency = InjiCertifyConfigManager.getproperty("generateDependencyJson");

			if (!"yes".equalsIgnoreCase(generateDependency)) {
				String testCasesToExecute = InjiCertifyConfigManager.getproperty("testCasesToExecute");
				if (testCasesToExecute != null && !testCasesToExecute.isBlank()) {
					DependencyResolver.loadDependencies(BaseTestCase.getTestCaseInterDependencyPath(useCaseToExecute));
					InjiCertifyUtil.testCasesInRunScope = DependencyResolver.getDependencies(testCasesToExecute.trim());
				}
			}

			// Needed for every use case, not just mosipid, else eSignet returns 403 Forbidden
			// Skip in CI: eSignetbaseurl points to external MOSIP host unreachable from CI network
			if (!"true".equals(System.getenv("CI"))) {
				AdminTestUtil.fetchAndStoreCsrfToken();
			}
			
			if (useCaseToExecute.equalsIgnoreCase("mosipid")
					|| useCaseToExecute.equalsIgnoreCase("mdocvp")) {

				if (useCaseToExecute.equalsIgnoreCase("mosipid")) {
					InjiCertifyUtil.dBCleanup();
				}

				// mdocvp also AddIdentity's a MOSIP UIN, so IDA needs the same CBEFF face.
				PartnerRegistration.deleteCertificates();
				registerDevicePartner();
				BiometricDataProvider.generateBiometricTestData("Registration");

				startTestRunner();

				if (useCaseToExecute.equalsIgnoreCase("mosipid")) {
					InjiCertifyUtil.dBCleanup();
				}
			} else {

				if ("true".equals(System.getenv("CI"))) {
					OTPListener.bTerminate = true;
				}
				startTestRunner();

			}
		} catch (Exception e) {
			LOGGER.error("Exception " + e.getMessage(), e);
			// Fatal init/run failure: exit non-zero instead of falling through to the success path
			System.exit(1);
		}

		if (useCaseToExecute.equalsIgnoreCase("landregistry")) {
			InjiCertifyUtil.landRegistryDBCleanup();
		}

		if (!"true".equals(System.getenv("CI"))) {
			KeycloakUserManager.removeUser();
			KeycloakUserManager.closeKeycloakInstance();
		}

		OTPListener.bTerminate = true;

		HealthChecker.bTerminate = true;

		// Used for generating the test case interdependency JSON file

		if ("yes".equalsIgnoreCase(generateDependency)) {
			LOGGER.info("Generating test case inter-dependencies");
			AdminTestUtil
					.generateTestCaseInterDependencies(BaseTestCase.getTestCaseInterDependencyPath(useCaseToExecute));
		} else {
			LOGGER.info("Skipping dependency generation");
		}

		System.exit(0);

	}

	/**
	 * {@link PartnerRegistration#deviceGeneration()} casts the partner-manager {@code response}
	 * field to {@link JSONObject}. An already-registered partner returns JSON null
	 * ({@code org.json.JSONObject$Null}), which is the only cast recovered here.
	 */
	private static void registerDevicePartner() {
		try {
			PartnerRegistration.deviceGeneration();
			return;
		} catch (ClassCastException alreadyRegistered) {
			if (!isNullDevicePartnerResponse(alreadyRegistered)) {
				throw alreadyRegistered;
			}
			LOGGER.error("Device partner is already registered; uploading its certificates", alreadyRegistered);
		}
		String partnerId = PartnerRegistration.deviceOrganizationName;
		JSONObject certificates = PartnerRegistration.getDeviceCertificates(partnerId, "DEVICE");
		String caCertificate = certificates.getString("caCertificate");
		String intermediateCertificate = certificates.getString("interCertificate");
		String partnerCertificate = certificates.getString("partnerCertificate");
		ClassCastException last = null;
		for (int attempt = 0; attempt < 4; attempt++) {
			PartnerRegistration.uploadCACertificate(caCertificate, "DEVICE");
			PartnerRegistration.uploadIntermediateCertificate(intermediateCertificate, "DEVICE");
			try {
				JSONObject signed = PartnerRegistration.uploadPartnerCertificate(partnerCertificate, "DEVICE",
						partnerId);
				PartnerRegistration.uploadSignedCertificate(signed.getString("signedCertificateData"), "DEVICE",
						partnerId, Boolean.TRUE);
				return;
			} catch (ClassCastException notYetTrusted) {
				last = notYetTrusted;
				LOGGER.info("Device partner certificate upload did not return signed data yet");
			}
		}
		throw new IllegalStateException(
				"Device partner certificate upload did not return signedCertificateData for " + partnerId, last);
	}

	/** True only for the JSON-null {@code response} cast inside {@code deviceGeneration}. */
	private static boolean isNullDevicePartnerResponse(ClassCastException failure) {
		String message = failure.getMessage();
		if (message == null || !message.contains("org.json.JSONObject$Null")) {
			return false;
		}
		for (StackTraceElement frame : failure.getStackTrace()) {
			if ("io.mosip.testrig.apirig.utils.PartnerRegistration".equals(frame.getClassName())
					&& "deviceGeneration".equals(frame.getMethodName())) {
				return true;
			}
		}
		return false;
	}

	public static void suiteSetup(String runType) {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			LOGGER.setLevel(Level.ALL);
		else
			LOGGER.info("Test Framework for Inji api Initialized");
		BaseTestCase.initialize();
		LOGGER.info("Done with BeforeSuite and test case setup! su TEST EXECUTION!\n\n");

		if (!runType.equalsIgnoreCase("JAR")) {
			AuthTestsUtil.removeOldMosipTempTestResource();
		}
		BaseTestCase.currentModule = BaseTestCase.runContext + GlobalConstants.INJICERTIFY;
		BaseTestCase.certsForModule = BaseTestCase.runContext + GlobalConstants.INJICERTIFY;
		AdminTestUtil.copymoduleSpecificAndConfigFile(GlobalConstants.INJICERTIFY);
		if (!"true".equals(System.getenv("CI"))) {
			BaseTestCase.otpListener = new OTPListener();
			BaseTestCase.otpListener.run();
		}
	}

	private static void setLogLevels() {
		AdminTestUtil.setLogLevel();
		OutputValidationUtil.setLogLevel();
		PartnerRegistration.setLogLevel();
		KeyCloakUserAndAPIKeyGeneration.setLogLevel();
		MispPartnerAndLicenseKeyGeneration.setLogLevel();
		JWKKeyUtil.setLogLevel();
		CertsUtil.setLogLevel();
		KernelAuthentication.setLogLevel();
		BaseTestCase.setLogLevel();
		InjiCertifyUtil.setLogLevel();
		KeycloakUserManager.setLogLevel();
		DBManager.setLogLevel();
		BiometricDataProvider.setLogLevel();
	}

	/**
	 * The method to start mosip testng execution
	 * 
	 * @throws IOException
	 */
	public static void startTestRunner() {
		File homeDir = null;
		String os = System.getProperty("os.name");
		LOGGER.info(os);
		if (getRunType().contains("IDE") || os.toLowerCase().contains("windows")) {
			homeDir = new File(System.getProperty("user.dir") + "/testNgXmlFiles");
			LOGGER.info("IDE :" + homeDir);
		} else {
			File dir = new File(System.getProperty("user.dir"));
			homeDir = new File(dir.getParent() + "/inji/testNgXmlFiles");
			LOGGER.info("ELSE :" + homeDir);
		}
		File[] files = homeDir.listFiles();
		if (files != null) {
			InjiCertifyUtil.currentUseCase = useCaseToExecute;

			for (File file : files) {
				TestNG runner = new TestNG();
				List<String> suitefiles = new ArrayList<>();

				if (file.getName().toLowerCase().contains("mastertestsuite")) {
					if (useCaseToExecute != null && useCaseToExecute.isBlank() == false) {
						BaseTestCase.setReportName(GlobalConstants.INJICERTIFY + "-" + useCaseToExecute);
					} else {
						BaseTestCase.setReportName(GlobalConstants.INJICERTIFY);
					}
					suitefiles.add(file.getAbsolutePath());
					runner.setTestSuites(suitefiles);
					System.getProperties().setProperty("testng.outpur.dir", "testng-report");
					runner.setOutputDirectory("testng-report");
					runner.run();
				}

			}
		} else {
			LOGGER.error("No files found in directory: " + homeDir);
		}

	}

	/**
	 * The method to return class loader resource path
	 * 
	 * @return String
	 * @throws IOException
	 */

	public static String getGlobalResourcePath() {
		if (cachedPath != null) {
			return cachedPath;
		}

		String path = null;
		if (getRunType().equalsIgnoreCase("JAR")) {
			path = new File(jarUrl).getParentFile().getAbsolutePath() + "/MosipTestResource/MosipTemporaryTestResource";
		} else if (getRunType().equalsIgnoreCase("IDE")) {
			path = new File(InjiTestRunner.class.getClassLoader().getResource("").getPath()).getAbsolutePath()
					+ "/MosipTestResource/MosipTemporaryTestResource";
			if (path.contains(GlobalConstants.TESTCLASSES))
				path = path.replace(GlobalConstants.TESTCLASSES, "classes");
		}

		if (path != null) {
			cachedPath = path;
			return path;
		} else {
			return "Global Resource File Path Not Found";
		}
	}

	public static String getResourcePath() {
		return getGlobalResourcePath();
	}

	public static String generatePulicKey() {
		String publicKey = null;
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2048, BaseTestCase.secureRandom);
			final KeyPair keypair = keyGenerator.generateKeyPair();
			publicKey = java.util.Base64.getEncoder().encodeToString(keypair.getPublic().getEncoded());
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(e.getMessage());
		}
		return publicKey;
	}

	public static KeyPairGenerator keyPairGen = null;

	public static KeyPairGenerator getKeyPairGeneratorInstance() {
		if (keyPairGen != null)
			return keyPairGen;
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(2048);

		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(e.getMessage());
		}

		return keyPairGen;
	}

	public static String generatePublicKeyForMimoto() {

		String vcString = "";
		try {
			KeyPairGenerator keyPairGenerator = getKeyPairGeneratorInstance();
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				pemWriter.writeObject(publicKey);
				pemWriter.flush();
				vcString = stringWriter.toString();
				if (System.getProperty("os.name").toLowerCase().contains("windows")) {
					vcString = vcString.replaceAll("\r\n", "\\\\n");
				} else {
					vcString = vcString.replaceAll("\n", "\\\\n");
				}
			} catch (Exception e) {
				throw e;
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
		return vcString;
	}

	public static String generateJWKPublicKey() {
		try {
			KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
			keyGenerator.initialize(2048, BaseTestCase.secureRandom);
			final KeyPair keypair = keyGenerator.generateKeyPair();
			RSAKey jwk = new RSAKey.Builder((RSAPublicKey) keypair.getPublic()).keyID("RSAKeyID")
					.keyUse(KeyUse.SIGNATURE).privateKey(keypair.getPrivate()).build();

			return jwk.toJSONString();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.error(e.getMessage());
			return null;
		}
	}

	public static Properties getproperty(String path) {
		Properties prop = new Properties();
		FileInputStream inputStream = null;
		try {
			File file = new File(path);
			inputStream = new FileInputStream(file);
			prop.load(inputStream);
		} catch (Exception e) {
			LOGGER.error(GlobalConstants.EXCEPTION_STRING_2 + e.getMessage());
		} finally {
			AdminTestUtil.closeInputStream(inputStream);
		}
		return prop;
	}

	/**
	 * The method will return mode of application started either from jar or eclipse
	 * ide
	 * 
	 * @return
	 */
	public static String getRunType() {
		if (InjiTestRunner.class.getResource("InjiTestRunner.class").getPath().contains(".jar"))
			return "JAR";
		else
			return "IDE";
	}
}

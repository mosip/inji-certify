package io.mosip.testrig.apirig.injicertify.utils;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.hibernate.Session;
import org.hibernate.jdbc.Work;

import io.mosip.testrig.apirig.dbaccess.DBManager;
import io.mosip.testrig.apirig.utils.AdminTestException;
public class ExtendedDBManager extends DBManager {
	private static Logger logger = Logger.getLogger(ExtendedDBManager.class);
	
	public static void setLogLevel() {
		if (InjiCertifyConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}
	
	public static void executeDBWithQueries(String dbURL, String dbUser, String dbPassword, String dbSchema,
			String dbQueries) throws AdminTestException {
		Session session = null;
		try {
			session = getDataBaseConnection(dbURL, dbUser, dbPassword, dbSchema);
			if (session != null)
				executeQueryAndInsertData(session, dbQueries);
			else
				throw new AdminTestException("Error:: While getting DB connection");
		} catch (Exception e) {
			logger.error("Error:: While executing DB Quiries." + e.getMessage());
			throw new AdminTestException(e.getMessage());
		} finally {
			if (session != null) {
				session.close();
			}
		}
	}
	
	public static void executeQueryAndInsertData(Session session, String deleteQuery) throws AdminTestException {
		try {
			if (session != null) {
				session.doWork(new Work() {
					@Override
					public void execute(Connection connection) throws SQLException {
						Statement statement = connection.createStatement();
						try {
							int rs = statement.executeUpdate(deleteQuery);
							if (rs > 0) {
								logger.info("Inserted Data successfully!");
							}
						} finally {
							statement.close();
						}
					}
				});
			}
		} catch (Exception e) {
			logger.error("Exception occured " + e.getMessage());
			throw new AdminTestException("Exception occured " + e.getMessage());
		} finally {
			closeDataBaseConnection(session);
		}
	}
	
	
}
package hu.sch.vir.auth.common;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.debug.Debug;
import hu.sch.vir.auth.VirJDBC;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.HashMap;
import java.util.Map;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;
import org.forgerock.openam.authentication.modules.oauth2.OAuthUtil;

/**
 *
 * @author balo
 */
public class VirDb implements AutoCloseable {

  private static final String JNDI_NAME = "java:comp/env/jdbc/sch";
  private Debug debug = null;
  private Connection conn;
  private final String userName;
  private final Map<String, Object> userRecord;

  public VirDb(String userName, Debug debug) throws AuthLoginException {
    this.debug = debug;
    this.userName = userName;

    userRecord = loadUser(userName);
  }

  public Object getUserData(VirDbColumns column) {
    return userRecord.get(column.val());
  }

  public String getUserDataAsString(VirDbColumns column) {
    return String.valueOf(getUserData(column));
  }

  public Long getUserDataAsLong(VirDbColumns column) {
    return Long.valueOf(getUserDataAsString(column));
  }

  private Connection getConn() throws NamingException, SQLException {

    if (conn == null || !conn.isValid(1000)) {
      if (conn != null) {
        close();
      }

      conn = getJndiConnection();
    }

    return conn;
  }

  private Connection getJndiConnection() throws NamingException, SQLException {
    final Context initctx = new InitialContext();
    final DataSource ds = (DataSource) initctx.lookup(JNDI_NAME);

    debugMsg("Datasource Acquired: " + ds.toString());

    return ds.getConnection();
  }

  /**
   * Loads the user record from the database.
   *
   * @param userName the vir login name of the user
   * @return the record in map. The keys are columns of the database.
   * @throws SQLException upon any database related error
   * @throws AuthLoginException when multiple entries or no entries found
   */
  private Map<String, Object> loadUser(final String userName) throws AuthLoginException {

    final Map<String, Object> attrs = new HashMap<>();
    debugMsg("PreparedStatement to build: " + Queries.GET_USER_DATA_STMT);

    try (PreparedStatement userDataStmt = getConn().prepareStatement(Queries.GET_USER_DATA_STMT.val())) {
      userDataStmt.setString(1, userName.toLowerCase());

      try (ResultSet results = userDataStmt.executeQuery()) {

        //parse the results.  should only be one item in one row.
        int index = 0;
        while (results.next()) {
          // do normal processing..its the first and last row
          index++;
          if (index > 1) {
            debugMsg("Too many results. UID should be a primary key");
            throw new AuthLoginException(VirJDBC.amAuthVirJDBC, "multiEntry", null);
          }

          final ResultSetMetaData meta = results.getMetaData();
          final int cols = meta.getColumnCount();
          for (int i = 1; i <= cols; ++i) {
            final String colName = meta.getColumnName(i);
            attrs.put(colName, results.getObject(colName));
          }
        }
        if (index == 0) {
          debugMsg("No results from your SQL query. UID should be valid");
          throw new AuthLoginException(VirJDBC.amAuthVirJDBC, "nullResult", null);
        }
      }
    } catch (NamingException | SQLException ex) {
      throw new AuthLoginException(ex);
    }

    return attrs;
  }

  /**
   * Queries the memberships from the database and assembles the full
   * entitlement string.
   *
   * @return full entitlement string
   * @throws AuthLoginException
   */
  public String getEntitlementString() throws AuthLoginException {

    final StringBuilder entitlementStr;
    final Long virid = getUserDataAsLong(VirDbColumns.VIRID);

    try (PreparedStatement stmt = getConn().prepareStatement(Queries.MEMBERSHIPS_STMT.val())) {

      stmt.setLong(1, virid);
      stmt.setLong(2, virid);
      try (ResultSet rs = stmt.executeQuery()) {

        entitlementStr = new StringBuilder(400);
        while (rs.next()) {
          //az első elem elé nem kell szeparátor
          if (!rs.isFirst()) {
            entitlementStr.append(VirSession.ENTITLEMENT_SEPARATOR);
          }

          final String groupName = rs.getString(VirDbColumns.GROUP_NAME.val());
          final int groupId = rs.getInt(VirDbColumns.GROUP_ID.val());
          final String post = rs.getString(VirDbColumns.POST_NAME.val());
          mapToEntitlement(entitlementStr, groupId, groupName, post);

          debugMsg("Entitlement in group: " + groupName + ", post: " + post);
        }
      }
    } catch (NamingException | SQLException e) {
      debugMsg("JDBC Exception:" + e.getMessage());
      throw new AuthLoginException(e);
    }

    return entitlementStr.toString();
  }

  /**
   * Appends the group's entitlement part to the given full entitlement
   * StringBuilder. Format of one entitlement:<br/>
   * <pre>urn:geant:niif.hu:sch.bme.hu:entitlement:gazdaságis:KIR fejlesztők és üzemeltetők:106</pre>
   *
   * @param sb StringBuilder of the entitlement string
   * @param groupId
   * @param groupName
   * @param entitlementType
   */
  private void mapToEntitlement(final StringBuilder sb, final int groupId,
          final String groupName, final String entitlementType) {

    sb.append(VirSession.ENTITLEMENT_PREFIX);
    sb.append(entitlementType);
    sb.append(VirSession.URN_SEPARATOR);
    sb.append(groupName);
    sb.append(VirSession.URN_SEPARATOR);
    sb.append(groupId);
  }

  /**
   * Updates the user's last login attribute in the database.
   *
   * @throws AuthLoginException
   */
  public void updateLastLoginTime() throws AuthLoginException {

    try (PreparedStatement stmt = getConn().prepareStatement(Queries.UPDATE_LASTLOGIN_STMT.val())) {
      stmt.setObject(1, getUserData(VirDbColumns.VIRID), Types.BIGINT);

      final int updatedRows = stmt.executeUpdate();
      debugMsg("Update lastlogin time, updated rows=" + updatedRows);
    } catch (NamingException | SQLException e) {
      debugMsg("JDBC Exception:" + e.getMessage());
      throw new AuthLoginException(e);
    }
  }

  @Deprecated
  public Map<String, Object> getUserRecord() {
    return userRecord;
  }

  private void debugMsg(final String msg) {
    if (debug == null) {
      OAuthUtil.debugMessage(msg);
    } else {
      if (debug.messageEnabled()) {
        debug.message(msg);
      }
    }
  }

  @Override
  public void close() {
    if (conn != null) {
      try {
        conn.close();
      } catch (SQLException ex) {
      }
    }
  }

}

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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

/**
 *
 * @author balo
 */
public class VirDb implements AutoCloseable {

  private static final String JNDI_NAME = "java:comp/env/jdbc/sch";
  private final Debug debug;
  private final Connection conn;
  private Map<String, Object> userRecord;

  public VirDb(Debug debug) throws AuthLoginException {
    this.debug = debug;
    try {
      conn = getJndiConnection();
    } catch (NamingException | SQLException ex) {
      debug.warning("Couldn't get database connection", ex);
      throw new AuthLoginException(ex);
    }
  }

  public Object getUserData(VirDbColumns column) {
    return userRecord.get(column.val());
  }

  public String getUserDataAsString(VirDbColumns column) {
    final String val = String.valueOf(getUserData(column));

    return val.equals("null") ? "" : val;
  }

  public Long getUserDataAsLong(VirDbColumns column) {
    return Long.valueOf(getUserDataAsString(column));
  }

  private Connection getJndiConnection() throws NamingException, SQLException {
    final Context initctx = new InitialContext();
    final DataSource ds = (DataSource) initctx.lookup(JNDI_NAME);

    if (debug.messageEnabled()) {
      debug.message("Datasource Acquired: " + ds.toString());
    }

    return ds.getConnection();
  }

  /**
   * Loads the user record from the database to initialize the object state for subsequent queries.
   *
   * @param userName The vir login name of the user.
   * @throws AuthLoginException When multiple entries or no entries found.
   */
  public void initialize(final String userName) throws AuthLoginException {
    if (userName == null || userName.isEmpty()) {
      throw new AuthLoginException(VirJDBC.amAuthVirJDBC, ErrorCode.NULL_RESULT.toString(), null);
    }
    final Map<String, Object> attrs = new HashMap<>();
    if (debug.messageEnabled()) {
      debug.message("PreparedStatement to build: " + Queries.GET_USER_DATA_STMT);
    }

    try (PreparedStatement userDataStmt = conn.prepareStatement(Queries.GET_USER_DATA_STMT.val())) {
      userDataStmt.setString(1, userName.toLowerCase());

      try (ResultSet results = userDataStmt.executeQuery()) {

        //parse the results.  should only be one item in one row.
        int index = 0;
        while (results.next()) {
          // do normal processing..its the first and last row
          index++;
          if (index > 1) {
            debug.error("Too many results. UID should be a primary key, userName: " + userName);
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
          debug.warning("No results from SQL query. UID should be valid");
          throw new AuthLoginException(VirJDBC.amAuthVirJDBC, ErrorCode.NULL_RESULT.toString(), null);
        }
      }
    } catch (SQLException ex) {
      debug.error("SQL error while querying user record", ex);
      throw new AuthLoginException(ex);
    }

    userRecord = Collections.unmodifiableMap(attrs);
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

    try (PreparedStatement stmt = conn.prepareStatement(Queries.MEMBERSHIPS_STMT.val())) {

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

          if (debug.messageEnabled()) {
            debug.message("Entitlement in group: " + groupName + ", post: " + post);
          }
        }
      }
    } catch (SQLException e) {
      debug.warning("JDBC Exception while getting entitlement string: " + e.getMessage());
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

    try (PreparedStatement stmt = conn.prepareStatement(Queries.UPDATE_LASTLOGIN_STMT.val())) {
      stmt.setObject(1, getUserData(VirDbColumns.VIRID), Types.BIGINT);

      final int updatedRows = stmt.executeUpdate();
      if (debug.messageEnabled()) {
        debug.message("Update lastlogin time, updated rows=" + updatedRows);
      }
    } catch (SQLException e) {
      debug.warning("JDBC Exception while updating last login time: " + e.getMessage());
      throw new AuthLoginException(e);
    }
  }

  @Deprecated
  public Map<String, Object> getUserRecord() {
    return userRecord;
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

/**
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2005 Sun Microsystems Inc. All Rights Reserved
 *
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * https://opensso.dev.java.net/public/CDDLv1.0.html or
 * opensso/legal/CDDLv1.0.txt See the License for the specific language
 * governing permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL Header Notice in each file
 * and include the License file at opensso/legal/CDDLv1.0.txt. If applicable,
 * add the following below the CDDL Header, with the fields enclosed by brackets
 * [] replaced by your own identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 *
 * $Id: VirJDBC.java,v 1.5 2008/08/28 21:56:45 madan_ranganath Exp $
 *
 * Portions Copyrighted 2011 ForgeRock Inc Portions Copyrighted 2012 Open Source
 * Solution Technology Corporation
 */
package hu.sch.vir.auth;

import hu.sch.vir.auth.password.JDBCTransformParams;
import hu.sch.vir.auth.password.JDBCPasswordSyntaxTransform;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import java.lang.reflect.Constructor;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.PreparedStatement;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.sql.DataSource;

public class VirJDBC extends AMLoginModule {

    private String userTokenId;
    private String userName;
    private String resultPassword;
    private char[] passwordCharArray;
    private java.security.Principal userPrincipal = null;
    private String errorMsg = null;
    public static final String amAuthVirJDBC = "amAuthVirJDBC";
    private static final Debug debug = Debug.getInstance(amAuthVirJDBC);
    private ResourceBundle bundle = null;
    private Map<String, Object> options;
    private String jndiName;
    private String passwordColumn;
    private Map sharedState;
    private boolean getCredentialsFromSharedState = false;
    private static final int MAX_NAME_LENGTH = 80;
    //config options
    private static final String JNDINAME_OPT = "VirJDBCJndiName";
    private static final String PASSWORD_COLUMN_OPT = "VirJDBCPasswordColumn";
    private static final String AUTHLEVEL_OPT = "iplanet-am-auth-virjdbc-auth-level";
    private static final String TRANSFORM = "hu.sch.vir.auth.password.HashTransform";
    //queries
    private static final String GET_USER_DATA_STMT = "select usr_password,usr_salt, "
            + "usr_id, usr_email, usr_firstname, usr_lastname, usr_nickname, "
            + "usr_screen_name, usr_dormitory, usr_room, usr_student_status "
            + "from users where LOWER(usr_screen_name) = ?";

    //user columns
    private static final String COL_UID = "usr_screen_name";
    private static final String COL_VIRID = "usr_id";
    private static final String COL_EMAIL = "usr_email";
    private static final String COL_FIRSTNAME = "usr_firstname";
    private static final String COL_LASTNAME = "usr_lastname";
    private static final String COL_NICK = "usr_nickname";
    private static final String COL_DORM = "usr_dormitory";
    private static final String COL_ROOM = "usr_room";
    private static final String COL_STUDENT_STATUS = "usr_student_status";
    //
    private static final String MEMBERSHIPS_STMT
            = "SELECT grp_membership.grp_id, groups.grp_name, poszttipus.pttip_name "
            + "FROM grp_membership JOIN groups USING (grp_id) "
            + "JOIN poszt ON poszt.grp_member_id = grp_membership.id "
            + "JOIN poszttipus ON poszt.pttip_id = poszttipus.pttip_id "
            + "WHERE (grp_membership.usr_id=? AND membership_end is null) "
            + "UNION "
            + "(SELECT grp_membership.grp_id, groups.grp_name, 'tag' AS pttip_name "
            + "FROM grp_membership JOIN groups USING (grp_id) "
            + "LEFT OUTER JOIN poszt ON poszt.grp_member_id = grp_membership.id "
            + "WHERE (poszt.pttip_id <> 6 OR poszt.pttip_id IS null) " //members under processing shouldn't get member rights
            + "AND usr_id = ? AND grp_membership.membership_end IS null) " //active member
            + "ORDER BY grp_id";
    //membership columns
    private static final String COL_GROUP_ID = "grp_id";
    private static final String COL_GROUP_NAME = "grp_name";
    private static final String COL_POST_NAME = "pttip_name";
    //
    private static final String UPDATE_LASTLOGIN_STMT = "UPDATE users "
            + "SET usr_lastlogin=NOW() "
            + "WHERE usr_id = ?";
    //session properties
    private static final String PROP_UID = "am.protected.uid";
    private static final String PROP_VIRID = "am.protected.schacPersonalUniqueId";
    private static final String PROP_STUDENT_STATUS = "am.protected.schacUserStatus";
    private static final String PROP_EMAIL = "am.protected.mail";
    private static final String PROP_FIRSTNAME = "am.protected.givenName";
    private static final String PROP_LASTNAME = "am.protected.sn";
    private static final String PROP_FULLNAME = "am.protected.cn";
    private static final String PROP_DISPLAY_NAME = "am.protected.displayName";
    private static final String PROP_NICK = "am.protected.eduPersonNickName";
    private static final String PROP_ROOM = "am.protected.roomNumber";
    private static final String PROP_ENTITLEMENT_V1 = "eduPersonEntitlement";
    private static final String PROP_ENTITLEMENT_V2 = "am.protected.eduPersonEntitlement";
    private static final String ENTITLEMENT_SEPARATOR = "|";
    private static final String ENTITLEMENT_PREFIX
            = "urn:geant:niif.hu:sch.bme.hu:entitlement:";
    private static final String URN_SEPARATOR = ":";
    private static final String VIRID_PREFIX
            = "urn:mace:terena.org:schac:personalUniqueID:hu:BME-SCH-VIR:person:";
    private static final String STUDENT_STATUS_PREFIX
            = "urn:mace:terena.org:schac:status:sch.hu:student_status:";
    private static final String LBR = "\n";

    /**
     * Constructor.
     */
    public VirJDBC() {
        debug.message("VirJDBC()");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(Subject subject, Map sharedState, Map options) {
        debug.message("in initialize...");
        java.util.Locale locale = getLoginLocale();
        bundle = amCache.getResBundle(amAuthVirJDBC, locale);

        if (debug.messageEnabled()) {
            debug.message("amAuthJDBC Authentication resource bundle locale="
                    + locale);
        }

        this.options = options;
        this.sharedState = sharedState;

        if (options != null) {
            try {
                debug.message("Using JNDI Retrieved Connection pool");
                jndiName = CollectionHelper.getMapAttr(options, JNDINAME_OPT);
                if (jndiName == null) {
                    debug.message("No JNDINAME for configuring");
                    errorMsg = "noJNDINAME";
                    return;
                } else {
                    if (debug.messageEnabled()) {
                        debug.message("Found config for JNDINAME: " + jndiName);
                    }
                }

                // and get the props that apply to both connection types
                passwordColumn = CollectionHelper.getMapAttr(
                        options, PASSWORD_COLUMN_OPT);
                if (passwordColumn == null) {
                    debug.message("No PASSWORDCOLUMN for configuring");
                    errorMsg = "noPASSWORDCOLUMN";
                    return;
                } else {
                    if (debug.messageEnabled()) {
                        debug.message("Found config for PASSWORDCOLUMN: "
                                + passwordColumn);
                    }
                }

                if (debug.messageEnabled()) {
                    debug.message("Plugin for TRANSFORM: " + TRANSFORM);
                }

                final String authLevel = CollectionHelper.getMapAttr(options, AUTHLEVEL_OPT);
                if (authLevel != null) {
                    try {
                        setAuthLevel(Integer.parseInt(authLevel));
                    } catch (NumberFormatException e) {
                        debug.error("Unable to set auth level " + authLevel, e);
                    }
                }

            } catch (Exception ex) {
                debug.error("JDBC Init Exception", ex);
            }
        }
    }

    private Connection getDatabaseConnection()
            throws NamingException, SQLException {

        final Context initctx = new InitialContext();
        final DataSource ds = (DataSource) initctx.lookup(jndiName);

        if (debug.messageEnabled()) {
            debug.message("Datasource Acquired: " + ds.toString());
        }

        return ds.getConnection();
    }

    /**
     * Processes the authentication request and sets session attributes.
     *
     * @param callbacks
     * @param state
     * @return <code>ISAuthConstants.LOGIN_SUCCEED</code> as succeeded;
     * <code>ISAuthConstants.LOGIN_IGNORE</code> as failed.
     * @throws AuthLoginException upon any failure. login state should be kept
     * on exceptions for status check in auth chaining.
     */
    @Override
    public int process(final Callback[] callbacks, final int state)
            throws AuthLoginException {

        final long processTimeBegin = System.currentTimeMillis();

        // return if this module is already done
        if (errorMsg != null) {
            throw new AuthLoginException(amAuthVirJDBC, errorMsg, null);
        }
        if (debug.messageEnabled()) {
            debug.message("State: " + state);
        }

        if (state != ISAuthConstants.LOGIN_START) {
            throw new AuthLoginException(amAuthVirJDBC, "invalidState", null);
        }

        String givenPassword;
        if (callbacks != null && callbacks.length == 0) {
            userName = (String) sharedState.get(getUserKey());
            givenPassword = (String) sharedState.get(getPwdKey());
            if (userName == null || givenPassword == null) {
                return ISAuthConstants.LOGIN_START;
            }
            getCredentialsFromSharedState = true;
        } else {
            userName = ((NameCallback) callbacks[0]).getName();
            if (debug.messageEnabled()) {
                debug.message("Authenticating this user: " + userName);
            }

            passwordCharArray = ((PasswordCallback) callbacks[1]).getPassword();
            givenPassword = String.valueOf(passwordCharArray);

            if (userName == null || userName.length() == 0) {
                throw new AuthLoginException(amAuthVirJDBC, "noUserName", null);
            }
        }

        // Check if they'return being a bit malicious with their UID.
        // SQL attacks will be handled by prepared stmt escaping.
        if (userName.length() > MAX_NAME_LENGTH) {
            throw new AuthLoginException(amAuthVirJDBC, "userNameTooLong", null);
        }

        String transformedPassword = null;
        final Map<String, Object> userRecord;
        try {
            try (Connection database = getDatabaseConnection()) {

                if (debug.messageEnabled()) {
                    debug.message("Connection Acquired: " + database.toString());
                }

                //Prepare the statement for execution
                if (debug.messageEnabled()) {
                    debug.message("PreparedStatement to build: " + GET_USER_DATA_STMT);
                }

                userRecord = loadUser(database);
                resultPassword = String.valueOf(userRecord.get(passwordColumn));

                transformedPassword = getTransformedPassword(givenPassword, userRecord);
            }
        } catch (NamingException | SQLException | AuthLoginException e) {
            if (getCredentialsFromSharedState && !isUseFirstPassEnabled()) {
                getCredentialsFromSharedState = false;
                return ISAuthConstants.LOGIN_START;
            }
            if (debug.messageEnabled()) {
                debug.message("JDBC Exception:", e);
            }
            throw new AuthLoginException(e);
        }

        // see if the passwords match
        if (transformedPassword != null && transformedPassword.equals(resultPassword)) {
            setUserSessionProperties(userRecord);
            setMembershipSessionProperties(userRecord);
            updateLastLoginTime(userRecord);
            userTokenId = userName;
            storeUsernamePasswd(userName, givenPassword);

            final long runningTime = System.currentTimeMillis() - processTimeBegin;
            debug.warning("the process() method ran " + runningTime + " ms");

            return ISAuthConstants.LOGIN_SUCCEED;
        } else {
            debug.message("password not match. Auth failed.");
            setFailureID(userName);
            throw new InvalidPasswordException(amAuthVirJDBC, "loginFailed",
                    null, userName, null);
        }
    }

    /**
     * Loads the user record from the database.
     *
     * @param database database connection. The method doesn't close this
     * connection.
     * @return the record in map. The keys are columns of the database.
     * @throws SQLException upon any database related error
     * @throws AuthLoginException when multiple entries or no entries found
     */
    private Map<String, Object> loadUser(final Connection database) throws SQLException, AuthLoginException {

        final Map<String, Object> userRecord = new HashMap<>();
        try (PreparedStatement thisStatement = database.prepareStatement(GET_USER_DATA_STMT)) {
            thisStatement.setString(1, userName.toLowerCase());
            if (debug.messageEnabled()) {
                debug.message("Statement to execute: " + thisStatement);
            }

            // execute the query
            try (ResultSet results = thisStatement.executeQuery()) {

                //parse the results.  should only be one item in one row.
                int index = 0;
                while (results.next()) {
                    // do normal processing..its the first and last row
                    index++;
                    if (index > 1) {
                        if (debug.messageEnabled()) {
                            debug.message("Too many results. UID should be a primary key");
                        }
                        throw new AuthLoginException(amAuthVirJDBC, "multiEntry", null);
                    }

                    final ResultSetMetaData meta = results.getMetaData();
                    final int cols = meta.getColumnCount();
                    for (int i = 1; i <= cols; ++i) {
                        final String colName = meta.getColumnName(i);
                        userRecord.put(colName, results.getObject(colName));
                    }
                }
                if (index == 0) {
                    // no results
                    if (debug.messageEnabled()) {
                        debug.message("No results from your SQL query."
                                + "UID should be valid");
                    }
                    throw new AuthLoginException(amAuthVirJDBC, "nullResult", null);
                }
            }
        }

        return userRecord;
    }

    /**
     * Returns the transformed password with the given plugin specified in
     * TRANSFORM.
     *
     * @param plainPassword the password given by the user
     * @param mapResult the database record of the user
     * @return the transformed password
     * @throws AuthLoginException upon any failure
     */
    private String getTransformedPassword(final String plainPassword, final Map<String, Object> mapResult)
            throws AuthLoginException {

        try {
            // Attempt to load the transforms constructor
            // that accepts a JDBCTransformParams instance.
            // If not found, use empty constructor.
            final Class classTransform = Class.forName(TRANSFORM);
            Constructor ctr = null;
            try {
                ctr = classTransform.getConstructor(
                        JDBCTransformParams.class);
            } catch (NoSuchMethodException | SecurityException ignored) {
            }

            JDBCPasswordSyntaxTransform syntaxTransform;
            if (ctr != null) {
                final JDBCTransformParams transformParams
                        = new JDBCTransformParams(options, mapResult);
                syntaxTransform = (JDBCPasswordSyntaxTransform) ctr.newInstance(new Object[]{transformParams});
            } else {
                syntaxTransform = (JDBCPasswordSyntaxTransform) classTransform.newInstance();
            }

            if (debug.messageEnabled()) {
                debug.message("Got my Transform Object" + syntaxTransform.toString());
            }

            final String transformedPassword = syntaxTransform.transform(plainPassword);

            if (debug.messageEnabled()) {
                debug.message("Password transformed: " + transformedPassword);
            }

            return transformedPassword;
        } catch (Exception e) {
            if (debug.messageEnabled()) {
                debug.message("Syntax Transform Exception:" + e.toString());
            }
            throw new AuthLoginException(e);
        }
    }

    /**
     * Returns principal of the authenticated user.
     *
     * @return Principal of the authenticated user.
     */
    @Override
    public java.security.Principal getPrincipal() {
        if (userPrincipal != null) {
            return userPrincipal;
        } else if (userTokenId != null) {
            userPrincipal = new JDBCPrincipal(userTokenId);
            return userPrincipal;
        } else {
            return null;
        }
    }

    /**
     * Cleans up the login state.
     */
    @Override
    public void destroyModuleState() {
        userTokenId = null;
        userPrincipal = null;
    }

    @Override
    public void nullifyUsedVars() {
        userName = null;
        resultPassword = null;
        passwordCharArray = null;
        errorMsg = null;
        bundle = null;
        options = null;
        jndiName = null;
        sharedState = null;
    }

    /**
     * Sets the user's attributes to the session from the given map.
     *
     * @param userRecord
     * @throws AuthLoginException if the user session is invalid
     */
    private void setUserSessionProperties(final Map<String, Object> userRecord)
            throws AuthLoginException {

        final String virid = String.valueOf(userRecord.get(COL_VIRID));
        final String uid = String.valueOf(userRecord.get(COL_UID));
        final String email = String.valueOf(userRecord.get(COL_EMAIL));
        final String studentStatus = String.valueOf(userRecord.get(COL_STUDENT_STATUS));
        final String firstName = String.valueOf(userRecord.get(COL_FIRSTNAME));
        final String lastName = String.valueOf(userRecord.get(COL_LASTNAME));
        final String nickname = String.valueOf(userRecord.get(COL_NICK));
        final String dormitory = String.valueOf(userRecord.get(COL_DORM));
        final String room = String.valueOf(userRecord.get(COL_ROOM));
        final String fullName = lastName + " " + firstName;

        if (debug.messageEnabled()) {
            final StringBuilder msg = new StringBuilder();
            msg.append(COL_VIRID).append("=").append(virid).append(LBR);
            msg.append(COL_EMAIL).append("=").append(email).append(LBR);
            msg.append(COL_STUDENT_STATUS).append("=").append(studentStatus).append(LBR);
            msg.append(COL_FIRSTNAME).append("=").append(firstName).append(LBR);
            msg.append(COL_LASTNAME).append("=").append(lastName).append(LBR);
            msg.append(PROP_FULLNAME).append("=").append(fullName).append(LBR);
            msg.append(COL_NICK).append("=").append(nickname).append(LBR);
            msg.append(COL_DORM).append("=").append(dormitory).append(LBR);
            msg.append(COL_ROOM).append("=").append(room).append(LBR);

            debug.message(msg.toString());
        }

        setUserSessionProperty(PROP_UID, uid);
        setUserSessionProperty(PROP_VIRID, VIRID_PREFIX + virid);
        setUserSessionProperty(PROP_EMAIL, email);
        setUserSessionProperty(PROP_STUDENT_STATUS, STUDENT_STATUS_PREFIX + studentStatus.toLowerCase());
        setUserSessionProperty(PROP_LASTNAME, lastName);
        setUserSessionProperty(PROP_FIRSTNAME, firstName);
        setUserSessionProperty(PROP_FULLNAME, fullName);
        setUserSessionProperty(PROP_DISPLAY_NAME, fullName);
        setUserSessionProperty(PROP_NICK, nickname);
        setUserSessionProperty(PROP_ROOM, dormitory + " " + room);
    }

    /**
     * Sets the entitlement attribute to the session.
     *
     * @param userRecord
     * @throws AuthLoginException if the db fails or the user session is invalid
     */
    private void setMembershipSessionProperties(final Map<String, Object> userRecord)
            throws AuthLoginException {

        try (Connection database = getDatabaseConnection()) {

            final String entitlementStr = getEntitlementString(database,
                    Long.valueOf(String.valueOf(userRecord.get(COL_VIRID))));

            if (debug.messageEnabled()) {
                debug.message(PROP_ENTITLEMENT_V1 + "=" + entitlementStr);
            }

            setUserSessionProperty(PROP_ENTITLEMENT_V1, entitlementStr);
            setUserSessionProperty(PROP_ENTITLEMENT_V2, entitlementStr);
        } catch (NamingException | SQLException e) {
            if (debug.messageEnabled()) {
                debug.message("JDBC Exception:", e);
            }
            throw new AuthLoginException(e);
        }
    }

    /**
     * Queries the memberships from the database and assembles the full
     * entitlement string.
     *
     * @param connection database connection. The method doesn't close this
     * connection
     * @param virid unique id of the user in the database
     * @return full entitlement string
     * @throws SQLException
     */
    private String getEntitlementString(final Connection connection, final Long virid)
            throws SQLException {

        final StringBuilder entitlementStr;

        try (PreparedStatement stmt = connection.prepareStatement(MEMBERSHIPS_STMT)) {

            stmt.setLong(1, virid);
            stmt.setLong(2, virid);
            try (ResultSet rs = stmt.executeQuery()) {

                entitlementStr = new StringBuilder(400);
                while (rs.next()) {
                    //az első elem elé nem kell szeparátor
                    if (!rs.isFirst()) {
                        entitlementStr.append(ENTITLEMENT_SEPARATOR);
                    }

                    final String groupName = rs.getString(COL_GROUP_NAME);
                    final int groupId = rs.getInt(COL_GROUP_ID);
                    final String post = rs.getString(COL_POST_NAME);
                    mapToEntitlement(entitlementStr, groupId, groupName, post);

                    if (debug.messageEnabled()) {
                        debug.message("Entitlement in group: " + groupName
                                + ", post: " + post);
                    }
                }
            }
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

        sb.append(ENTITLEMENT_PREFIX);
        sb.append(entitlementType);
        sb.append(URN_SEPARATOR);
        sb.append(groupName);
        sb.append(URN_SEPARATOR);
        sb.append(groupId);
    }

    /**
     * Updates the user's last login attribute in the database.
     *
     * @param userRecord
     * @throws AuthLoginException
     */
    private void updateLastLoginTime(final Map<String, Object> userRecord)
            throws AuthLoginException {

        try (Connection conn = getDatabaseConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement(UPDATE_LASTLOGIN_STMT)) {
                stmt.setObject(1, userRecord.get(COL_VIRID), Types.BIGINT);

                final int updatedRows = stmt.executeUpdate();
                if (debug.messageEnabled()) {
                    debug.message("Update lastlogin time, updated rows=" + updatedRows);
                }
            }
        } catch (NamingException | SQLException e) {
            if (debug.messageEnabled()) {
                debug.message("JDBC Exception:", e);
            }
            throw new AuthLoginException(e);
        }
    }
}

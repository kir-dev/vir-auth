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

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import hu.sch.vir.auth.common.Queries;
import hu.sch.vir.auth.common.VirDbColumns;
import hu.sch.vir.auth.common.VirSession;
import hu.sch.vir.auth.password.HashTransform;
import hu.sch.vir.auth.password.JDBCPasswordSyntaxTransform;
import hu.sch.vir.auth.password.JDBCTransformParams;
import java.lang.reflect.Constructor;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
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
    private Map sharedState;
    private boolean getCredentialsFromSharedState = false;
    private static final int MAX_NAME_LENGTH = 80;
    //config options
    private static final String JNDINAME_OPT = "VirJDBCJndiName";
    private static final String AUTHLEVEL_OPT = "iplanet-am-auth-virjdbc-auth-level";
    private static final String USED_ALGORITHM = "SHA-1";
    private static final String TRANSFORM = "hu.sch.vir.auth.password.HashTransform";
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
                    debug.message("PreparedStatement to build: " + Queries.GET_USER_DATA_STMT);
                }

                userRecord = loadUser(database);
                resultPassword = String.valueOf(userRecord.get(VirDbColumns.PASSWORD.val()));

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
        try (PreparedStatement thisStatement = database.prepareStatement(Queries.GET_USER_DATA_STMT.val())) {
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
                //setup HashTransform manually, we won't config these in runtime...
                final Map<String, Set<String>> transformOptions = new HashMap<>();

                transformOptions.put(HashTransform.ALGORITHM, asSet(USED_ALGORITHM));
                transformOptions.put(HashTransform.SALTCOLUMN, asSet(VirDbColumns.PW_SALT.val()));
                transformOptions.put(HashTransform.SALT_AFTER_PASSWORD,
                        asSet(Boolean.TRUE.toString()));

                final JDBCTransformParams transformParams
                        = new JDBCTransformParams(transformOptions, mapResult);
                syntaxTransform = (JDBCPasswordSyntaxTransform) ctr.newInstance(new Object[]{transformParams});
            } else {
                syntaxTransform = (JDBCPasswordSyntaxTransform) classTransform.newInstance();
            }

            if (debug.messageEnabled()) {
                debug.message("Got my Transform Object: " + syntaxTransform.toString());
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

        final String virid = String.valueOf(userRecord.get(VirDbColumns.VIRID.val()));
        final String uid = String.valueOf(userRecord.get(VirDbColumns.UID.val()));
        final String email = String.valueOf(userRecord.get(VirDbColumns.EMAIL.val()));
        final String studentStatus = String.valueOf(userRecord.get(VirDbColumns.STUDENT_STATUS.val()));
        final String firstName = String.valueOf(userRecord.get(VirDbColumns.FIRSTNAME.val()));
        final String lastName = String.valueOf(userRecord.get(VirDbColumns.LASTNAME.val()));
        final String nickname = String.valueOf(userRecord.get(VirDbColumns.NICK.val()));
        final String dormitory = String.valueOf(userRecord.get(VirDbColumns.DORM.val()));
        final String room = String.valueOf(userRecord.get(VirDbColumns.ROOM.val()));
        final String fullName = lastName + " " + firstName;

        if (debug.messageEnabled()) {
            debug.message(VirDbColumns.VIRID + "=" + virid + LBR
            + VirDbColumns.EMAIL + "=" + email + LBR
            + VirDbColumns.STUDENT_STATUS + "=" + studentStatus + LBR
            + VirDbColumns.FIRSTNAME + "=" + firstName + LBR
            + VirDbColumns.LASTNAME + "=" + lastName + LBR
            + VirSession.PROP_FULLNAME + "=" + fullName + LBR
            + VirDbColumns.NICK + "=" + nickname + LBR
            + VirDbColumns.DORM + "=" + dormitory + LBR
            + VirDbColumns.ROOM + "=" + room + LBR);
        }

        setUserSessionProperty(VirSession.PROP_UID.val(), uid);
        setUserSessionProperty(VirSession.PROP_VIRID.val(), VirSession.VIRID_PREFIX + virid);
        setUserSessionProperty(VirSession.PROP_EMAIL.val(), email);
        setUserSessionProperty(VirSession.PROP_STUDENT_STATUS.val(), VirSession.STUDENT_STATUS_PREFIX + studentStatus.toLowerCase());
        setUserSessionProperty(VirSession.PROP_LASTNAME.val(), lastName);
        setUserSessionProperty(VirSession.PROP_FIRSTNAME.val(), firstName);
        setUserSessionProperty(VirSession.PROP_FULLNAME.val(), fullName);
        setUserSessionProperty(VirSession.PROP_DISPLAY_NAME.val(), fullName);
        setUserSessionProperty(VirSession.PROP_NICK.val(), nickname);
        setUserSessionProperty(VirSession.PROP_ROOM.val(), dormitory + " " + room);
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
                    Long.valueOf(String.valueOf(userRecord.get(VirDbColumns.VIRID.val()))));

            if (debug.messageEnabled()) {
                debug.message(VirSession.PROP_ENTITLEMENT_V1 + "=" + entitlementStr);
            }

            setUserSessionProperty(VirSession.PROP_ENTITLEMENT_V1.val(), entitlementStr);
            setUserSessionProperty(VirSession.PROP_ENTITLEMENT_V2.val(), entitlementStr);
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

        try (PreparedStatement stmt = connection.prepareStatement(Queries.MEMBERSHIPS_STMT.val())) {

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
     * @param userRecord
     * @throws AuthLoginException
     */
    private void updateLastLoginTime(final Map<String, Object> userRecord)
            throws AuthLoginException {

        try (Connection conn = getDatabaseConnection()) {
            try (PreparedStatement stmt = conn.prepareStatement(Queries.UPDATE_LASTLOGIN_STMT.val())) {
                stmt.setObject(1, userRecord.get(VirDbColumns.VIRID.val()), Types.BIGINT);

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

    /**
     * Creates an <i>immutable</i> {@code HashSet} instance containing the given
     * elements in unspecified order.
     *
     * @param <E>
     * @param elements the elements that the set should contain
     * @return a new {@code HashSet} containing those elements (minus
     * duplicates)
     */
    public static <E> Set<E> asSet(final E... elements) {
        if (elements == null) {
            return new HashSet<>(0);
        }

        final Set<E> set = new HashSet<>(elements.length);
        Collections.addAll(set, elements);
        return Collections.unmodifiableSet(set);
    }
}

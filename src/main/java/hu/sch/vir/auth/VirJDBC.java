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
    private static final String JNDINAME_OPT = "VirJDBCJndiName";
    private static final String PASSWORD_COLUMN_OPT = "VirJDBCPasswordColumn";
    private static final String AUTHLEVEL_OPT = "iplanet-am-auth-virjdbc-auth-level";
    private static final String STATEMENT = "select usr_password,usr_salt from users where LOWER(usr_screen_name) = ?";
    private static final String TRANSFORM = "hu.sch.vir.auth.password.HashTransform";
    private Map sharedState;
    private boolean getCredentialsFromSharedState = false;
    private static final int MAX_NAME_LENGTH = 80;

    /**
     * Constructor.
     */
    public VirJDBC() {
        debug.message("VirJDBC()");
    }

    /**
     * Initializes parameters.
     *
     * @param subject
     * @param sharedState
     * @param options
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

    /**
     * Processes the authentication request.
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
        try {
            final Context initctx = new InitialContext();
            final DataSource ds = (DataSource) initctx.lookup(jndiName);

            if (debug.messageEnabled()) {
                debug.message("Datasource Acquired: " + ds.toString());
            }

            try (Connection database = ds.getConnection()) {

                if (debug.messageEnabled()) {
                    debug.message("Connection Acquired: " + database.toString());
                }

                //Prepare the statement for execution
                if (debug.messageEnabled()) {
                    debug.message("PreparedStatement to build: " + STATEMENT);
                }

                final Map<String, Object> mapResult = loadUser(database);
                resultPassword = String.valueOf(mapResult.get(passwordColumn));

                transformedPassword = getTransformedPassword(givenPassword, mapResult);
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
            userTokenId = userName;
            storeUsernamePasswd(userName, givenPassword);
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

        Map<String, Object> mapResult = new HashMap<>();
        try (PreparedStatement thisStatement = database.prepareStatement(STATEMENT)) {
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
                        mapResult.put(colName, results.getObject(colName));
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

        return mapResult;
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
}

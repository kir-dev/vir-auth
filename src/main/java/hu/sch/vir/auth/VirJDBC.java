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
 * Portions Copyrighted 2011 ForgeRock Inc
 * Portions Copyrighted 2012 Open Source Solution Technology Corporation
 */
package hu.sch.vir.auth;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.spi.InvalidPasswordException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import hu.sch.vir.auth.common.Helpers;
import hu.sch.vir.auth.common.VirDb;
import hu.sch.vir.auth.common.VirDbColumns;
import hu.sch.vir.auth.common.VirSession;
import hu.sch.vir.auth.password.HashTransform;
import hu.sch.vir.auth.password.JDBCPasswordSyntaxTransform;
import hu.sch.vir.auth.password.JDBCTransformParams;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

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
    private Map sharedState;
    private boolean getCredentialsFromSharedState = false;
    private static final int MAX_NAME_LENGTH = 80;
    //config options
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

        try (VirDb virDb = new VirDb(debug)) {
          virDb.initialize(userName);
          String transformedPassword = getTransformedPassword(givenPassword, virDb);

          // see if the passwords match
          resultPassword = virDb.getUserDataAsString(VirDbColumns.PASSWORD);
          if (transformedPassword != null && transformedPassword.equals(resultPassword)) {
              setUserSessionProperties(virDb);
              setMembershipSessionProperties(virDb);
              virDb.updateLastLoginTime();
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
        } catch (AuthLoginException e) {
          if (getCredentialsFromSharedState && !isUseFirstPassEnabled()) {
              getCredentialsFromSharedState = false;
              return ISAuthConstants.LOGIN_START;
          }
          if (debug.messageEnabled()) {
              debug.message("JDBC Exception:", e);
          }
          throw new AuthLoginException(e);
        }
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
    private String getTransformedPassword(final String plainPassword, VirDb virDb)
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

                transformOptions.put(HashTransform.ALGORITHM, Helpers.asSet(VirJDBC.USED_ALGORITHM));
                transformOptions.put(HashTransform.SALTCOLUMN, Helpers.asSet(VirDbColumns.PW_SALT.val()));
                transformOptions.put(HashTransform.SALT_AFTER_PASSWORD,
                        Helpers.asSet(Boolean.TRUE.toString()));

                final JDBCTransformParams transformParams
                        = new JDBCTransformParams(transformOptions, virDb.getUserRecord());
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
        sharedState = null;
    }

    /**
     * Sets the user's attributes to the session from the given map.
     *
     * @param userRecord
     * @throws AuthLoginException if the user session is invalid
     */
    private void setUserSessionProperties(final VirDb virDb)
            throws AuthLoginException {

        final String virid = virDb.getUserDataAsString(VirDbColumns.VIRID);
        final String uid = virDb.getUserDataAsString(VirDbColumns.UID);
        final String email = virDb.getUserDataAsString(VirDbColumns.EMAIL);
        final String studentStatus = virDb.getUserDataAsString(VirDbColumns.STUDENT_STATUS);
        final String firstName = virDb.getUserDataAsString(VirDbColumns.FIRSTNAME);
        final String lastName = virDb.getUserDataAsString(VirDbColumns.LASTNAME);
        final String nickname = virDb.getUserDataAsString(VirDbColumns.NICK);
        final String dormitory = virDb.getUserDataAsString(VirDbColumns.DORM);
        final String room = virDb.getUserDataAsString(VirDbColumns.ROOM);
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
    private void setMembershipSessionProperties(final VirDb virDb)
            throws AuthLoginException {

      final String entitlementStr = virDb.getEntitlementString();

      debug.message(VirSession.PROP_ENTITLEMENT_V1 + "=" + entitlementStr);

      setUserSessionProperty(VirSession.PROP_ENTITLEMENT_V1.val(), entitlementStr);
      setUserSessionProperty(VirSession.PROP_ENTITLEMENT_V2.val(), entitlementStr);
    }

}

/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011-2012 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 *
 * Portions Copyrighted 2012 Sam Crawford
 */
package hu.sch.vir.auth.password;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import hu.sch.vir.auth.VirJDBC;
import org.apache.commons.codec.binary.Base64;

/**
 * An implementation of the VirJDBC Password Syntax Transform that hashes input
 * using a MessageDigest-supported algorithm (SHA-256 by default). An optional
 * salt may be supplied.
 */
public class HashTransform implements JDBCPasswordSyntaxTransform {

    private static final Debug debug = Debug.getInstance(VirJDBC.amAuthVirJDBC);
    //
    public static final String SALTCOLUMN = "VirJDBCSaltColumn";
    public static final String SALT_AFTER_PASSWORD = "VirJDBCSaltAfterPassword";
    public static final String ALGORITHM = "VirJDBCTransformHashAlgorithm";
    //
    static final String DEFAULT_ALGORITHM = "SHA-256";
    //
    protected final JDBCTransformParams params;

    /**
     * Creates a new instance of {@link HashTransform} with no options.
     * @throws com.sun.identity.authentication.spi.AuthLoginException
     */
    public HashTransform() throws AuthLoginException {
        this(null);
    }

    /**
     * Creates a new instance of {@link HashTransform} with parameters. These
     * parameters should include (1) the options map from the JDBC auth module
     * and (2) the result set from the database row that represents the user we
     * are trying to validate.
     * <br/>
     * Note: it does NOT create defensive copy of the supplied
     * {@link JDBCTransformParams} argument
     *
     * @param params
     * @throws AuthLoginException when the parameter is null
     */
    public HashTransform(final JDBCTransformParams params) throws AuthLoginException {
        if (params == null) {
            throw new AuthLoginException("JDBCTransformParams is null!");
        }

        this.params = params;
    }

    /**
     * Returns the hash of the input, optionally with the salt. If the salt is
     * null or empty it will be ignored. Depends from value of the
     * {@link #SALT_AFTER_PASSWORD} option, the salt will be appended before or
     * after the password.
     *
     * @param input Password before transform
     * @return Hashed password with salt as a base64 encoded string
     * @throws AuthLoginException
     */
    @Override
    public String transform(final String input) throws AuthLoginException {
        if (input == null) {
            throw new AuthLoginException("No input to the HashTransform!");
        }

        try {
            // Salt (from result set)
            String salt = null;
            final String saltColumn = CollectionHelper.getMapAttr(
                    params.getOptions(), SALTCOLUMN);
            if (saltColumn != null && !saltColumn.equals("")) {
                salt = (String) params.getResultSet().get(saltColumn);
            }

            // Algorithm (static)
            final String algorithm = CollectionHelper.getMapAttr(
                    params.getOptions(), ALGORITHM, DEFAULT_ALGORITHM);

            if (debug.messageEnabled()) {
                debug.message("Using transform algorithm=" + algorithm);
            }

            return hash(algorithm, input, salt);
        } catch (Exception e) {
            throw new AuthLoginException("Could not hash input", e);
        }
    }

    /**
     * Hashes the input using the supplied algorithm. If the salt is null or
     * empty it will be ignored. Depends from value of the
     * {@link #SALT_AFTER_PASSWORD} option, the salt will be appended before or
     * after the password. The returned value is a base64 encoded string
     * representation of the hash.
     *
     * @param algorithm The algorithm to use (e.g. MD5, SHA-256)
     * @param password The input to hash
     * @param salt The salt to prepend / append after the input (may be null)
     * @return Hashed input as base64 encoded string
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    private String hash(final String algorithm, final String input, final String salt)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {

        final MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] bytes = null;
        // Need to synchronize digest as it's succeptible to race
        // conditions
        synchronized (digest) {
            digest.reset();

            if (salt != null && salt.length() > 0) {
                if (isSaltAfterPassword()) {
                    digest.update(input.getBytes("UTF-8"));
                    digest.update(Base64.decodeBase64(salt));
                } else {
                    digest.update(Base64.decodeBase64(salt));
                    digest.update(input.getBytes("UTF-8"));
                }
            } else { //hash without salt
                digest.update(input.getBytes("UTF-8"));
            }

            bytes = digest.digest();
        }

        debug.message("hash() method returning=" + Base64.encodeBase64String(bytes).trim());

        return Base64.encodeBase64String(bytes).trim();
    }

    /**
     * Get the value of {@link #SALT_AFTER_PASSWORD} option from the map.
     * Returns false if the option is null or empty.
     *
     * @return true, only if the option set to "true".
     */
    private boolean isSaltAfterPassword() {
        boolean result = false;

        final String saltAfterPasswordOpt = CollectionHelper.getMapAttr(
                params.getOptions(), SALT_AFTER_PASSWORD);
        if (saltAfterPasswordOpt != null && !saltAfterPasswordOpt.equals("")) {
            result = Boolean.valueOf(saltAfterPasswordOpt);
        }

        if (debug.messageEnabled()) {
            debug.message("isSaltAfterPassword=" + result);
        }

        return result;
    }
}

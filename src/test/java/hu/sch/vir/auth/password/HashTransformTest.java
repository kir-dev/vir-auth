package hu.sch.vir.auth.password;

import hu.sch.vir.auth.password.HashTransform;
import hu.sch.vir.auth.password.JDBCTransformParams;
import com.sun.identity.authentication.spi.AuthLoginException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import org.testng.annotations.Test;

/**
 * Tests {@link HashTransform} class.
 */
public class HashTransformTest {

    private final String PASSWORD_SALT_COLUMN = "passw_salt";
    private static final String CLEAR_TEXT_PASSW = "áű!ú3ő/x!~.;`";
    //
    private final TestPassword sha1WithBeforeSalt =
            new TestPassword(CLEAR_TEXT_PASSW, "SHA-1", false, "xbHDoTZfZ3NoLS7FsDvDiScuNSk=", "qs6ceo0v1emJIvMkqk3S1DqBQB4=");
    //
    private final TestPassword sha1WithAfterSalt =
            new TestPassword(CLEAR_TEXT_PASSW, "SHA-1", true, "xbHDoTZfZ3M1Pi0oPScuNSk=", "eWUToXSUe5sZiNz8gu+64HXn/94=");
    //
    private final TestPassword sha256WithoutSalt =
            new TestPassword(CLEAR_TEXT_PASSW, "", false, "", "OSE70wBqNO9VIYvc7/p0WGzyzSr5TBjgG8bFXHbLcYU=");
    //
    private final TestPassword sha256WithBeforeSalt =
            new TestPassword(CLEAR_TEXT_PASSW, "", false, "xbHDoTY0ISUvLS7FsDvDiScuNSk=", "CWj+gSlexd/9bU9h45E/5PgB061K/a8p2PT8tvEENlg=");
    //
    private final TestPassword sha256WithAfterSalt =
            new TestPassword(CLEAR_TEXT_PASSW, "", true, "xbHDoTY0ISUvc2gtLsWwO8OJJy41KQ==", "4HCUBCODyiyz+pwJe4T/RdhBojLyZm6AOAYJy0BQkJo=");

    /**
     * Tests if we don't give {@link JDBCTransformParams} parameter.
     *
     * @throws AuthLoginException
     */
    @Test(expectedExceptions = {AuthLoginException.class})
    public void createWithoutParams() throws AuthLoginException {
        final HashTransform test = new HashTransform();
    }

    /**
     * Tests if we give null {@link JDBCTransformParams} parameter.
     *
     * @throws AuthLoginException
     */
    @Test(expectedExceptions = {AuthLoginException.class})
    public void createWithNullParams() throws AuthLoginException {
        final HashTransform test = new HashTransform(null);
    }

    /**
     * Tests if we give null password input.
     *
     * @throws AuthLoginException
     */
    @Test(expectedExceptions = {AuthLoginException.class})
    public void nullInput() throws AuthLoginException {
        //create not test parameters object with non-null maps
        final JDBCTransformParams testParams =
                new JDBCTransformParams(Collections.emptyMap(), Collections.emptyMap());
        new HashTransform(testParams).transform(null);
    }

    /**
     * Tests the default values. Hash password with SHA-256, without salt. It
     * creates an instance from this class to use the overriden
     * {@link #getMessageDigest(java.lang.String)} method
     *
     * @throws AuthLoginException
     */
    @Test
    public void defaultValues() throws AuthLoginException {

        final JDBCTransformParams testparams =
                new JDBCTransformParams(Collections.emptyMap(), Collections.emptyMap());

        final HashTransform transform = new HashTransform(testparams);
        final String transformedPassw = transform.transform(sha256WithoutSalt.getClearText());

        assert sha256WithoutSalt.getHashed().equals(transformedPassw);
    }

    /**
     * Tests if we can check salted password with default algorithm. Hash
     * password with SHA-256, with salt appended before the password
     *
     * @throws AuthLoginException
     */
    @Test
    public void beforeSaltAndDefaultAlgo() throws AuthLoginException {
        final HashTransform transform = getConfiguredHashTransformFor(sha256WithBeforeSalt);
        final String transformedPassw = transform.transform(sha256WithBeforeSalt.getClearText());

        assert sha256WithBeforeSalt.getHashed().equals(transformedPassw);
    }

    /**
     * Tests if we can check salted password with default algorithm. Hash
     * password with SHA-256, with salt appended after the password
     *
     * @throws AuthLoginException
     */
    @Test
    public void afterSaltAndDefaultAlgo() throws AuthLoginException {
        final HashTransform transform = getConfiguredHashTransformFor(sha256WithAfterSalt);
        final String transformedPassw = transform.transform(sha256WithAfterSalt.getClearText());

        assert sha256WithAfterSalt.getHashed().equals(transformedPassw);
    }

    /**
     * Tests if we can check salted password with custom algorithm. Hash
     * password with SHA-1, with salt appended before the password
     *
     * @throws AuthLoginException
     */
    @Test
    public void beforeSaltAndCustomAlgo() throws AuthLoginException {
        final HashTransform transform = getConfiguredHashTransformFor(sha1WithBeforeSalt);
        final String transformedPassw = transform.transform(sha1WithBeforeSalt.getClearText());

        assert sha1WithBeforeSalt.getHashed().equals(transformedPassw);
    }

    /**
     * Tests if we can check salted password with custom algorithm. Hash
     * password with SHA-1, with salt appended after the password
     *
     * @throws AuthLoginException
     */
    @Test
    public void afterSaltAndCustomAlgo() throws AuthLoginException {
        final HashTransform transform = getConfiguredHashTransformFor(sha1WithAfterSalt);
        final String transformedPassw = transform.transform(sha1WithAfterSalt.getClearText());

        assert sha1WithAfterSalt.getHashed().equals(transformedPassw);
    }

    private HashTransform getConfiguredHashTransformFor(final TestPassword testPassword)
            throws AuthLoginException {

        final HashMap options = new HashMap();
        //set algorithm
        if (!testPassword.getAlg().isEmpty()) {
            final HashSet algSet = new HashSet();
            algSet.add(testPassword.getAlg());
            options.put(HashTransform.ALGORITHM, algSet);
        }

        //set salt column option
        final HashSet saltSet = new HashSet();
        saltSet.add(PASSWORD_SALT_COLUMN);
        options.put(HashTransform.SALTCOLUMN, saltSet);

        //set salt after password option
        final HashSet saltAfterPasswordSet = new HashSet();
        saltAfterPasswordSet.add(testPassword.isSaltAfterPassword().toString());
        options.put(HashTransform.SALT_AFTER_PASSWORD, saltAfterPasswordSet);

        //set salt value
        final HashMap mapResult = new HashMap();
        mapResult.put(PASSWORD_SALT_COLUMN, testPassword.getSalt());

        final JDBCTransformParams params = new JDBCTransformParams(options, mapResult);
        return new HashTransform(params);
    }

    /**
     * An internal datastore class to simplify test inputs.
     */
    private class TestPassword {

        private String clearText; //in utf-8
        private String alg; //empty means default
        private boolean saltAfterPassword;
        private String salt; //base64 encoded
        private String hashed; //base64 encoded

        public TestPassword(final String clearText, final String alg,
                final boolean saltAfterPassword, final String salt, final String hashed) {

            this.clearText = clearText;
            this.alg = alg;
            this.saltAfterPassword = saltAfterPassword;
            this.salt = salt;
            this.hashed = hashed;
        }

        public String getClearText() {
            return clearText;
        }

        public String getAlg() {
            return alg;
        }

        public Boolean isSaltAfterPassword() {
            return Boolean.valueOf(saltAfterPassword);
        }

        public String getSalt() {
            return salt;
        }

        public String getHashed() {
            return hashed;
        }
    }
}

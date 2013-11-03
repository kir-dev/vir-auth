/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2011-2013 ForgeRock AS. All rights reserved.
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

import com.sun.identity.authentication.spi.AuthLoginException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Class for extends the password transform capabilites. An instance can store
 * the options of the modul and the resultset of the query. The instance can be
 * passed to the constructor of a class which implements
 * {@link JDBCPasswordSyntaxTransform}.
 */
public class JDBCTransformParams {

    private final Map options;
    private final Map resultSet;

    /**
     * Creates a new instance of {@link JDBCTransformParams}. You can pass empty
     * maps, but arguments can't be null.
     *
     * @param options of the modul instance, can't be null.
     * @param resultSet of the preparedstatement, can't be null.
     * @throws AuthLoginException when {@code options} or {@code resultset}
     * argument is null
     */
    public JDBCTransformParams(final Map options, final Map resultSet)
            throws AuthLoginException {

        if (options == null) {
            throw new AuthLoginException("options can't be null in JDBCTransformParams");
        }
        if (resultSet == null) {
            throw new AuthLoginException("resultSet can't be null in JDBCTransformParams");
        }

        this.options = new HashMap(options);
        this.resultSet = new HashMap(resultSet);
    }

    /**
     * Returns an unmodifiable view of the options map.
     *
     * @return
     */
    public Map getOptions() {
        return Collections.unmodifiableMap(options);
    }

    /**
     * Returns an unmodifiable view of the resultSet map.
     *
     * @return
     */
    public Map getResultSet() {
        return Collections.unmodifiableMap(resultSet);
    }
}

//
// ========================================================================
// Copyright (c) 1995 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//

package org.eclipse.jetty.security;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import javax.security.auth.Subject;

import org.eclipse.jetty.security.authentication.SessionAuthentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.util.Callback;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyArray;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

public class DefaultIdentityServiceTest
{
    @Test
    public void testNullRolesUserIdentity() throws Exception
    {
        // A JASPI ServerAuthModule that sends no GroupPrincipalCallback results in null roles.
        DefaultIdentityService identityService = new DefaultIdentityService();
        Principal principal = new UserPrincipal("jaspiUser", null);
        UserIdentity userIdentity = identityService.newUserIdentity(new Subject(), principal, null);
        assertThat(userIdentity.getRoles(), emptyArray());
        assertThat(userIdentity.isUserInRole("admin"), is(false));

        // The identity can still be cached in the session, and the credentials are not serialized.
        SessionAuthentication sessionAuthentication = new SessionAuthentication("TEST", userIdentity, "secretPassword");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes))
        {
            out.writeObject(sessionAuthentication);
        }
        String serialized = bytes.toString(StandardCharsets.ISO_8859_1);
        assertThat(serialized, containsString("jaspiUser"));
        assertThat(serialized, not(containsString("secretPassword")));
    }

    @Test
    public void testDefaultIdentityService() throws Exception
    {
        Server server = new Server();
        SecurityHandler securityHandler = new SecurityHandler.PathMapped();
        TestAuthenticator authenticator = new TestAuthenticator();
        securityHandler.setAuthenticator(authenticator);

        try
        {
            server.setHandler(securityHandler);
            server.start();

            // The DefaultIdentityService should have been created by default.
            assertThat(securityHandler.getIdentityService(), instanceOf(DefaultIdentityService.class));
            assertThat(authenticator.getIdentityService(), instanceOf(DefaultIdentityService.class));
        }
        finally
        {
            server.stop();
        }
    }

    public static class TestAuthenticator implements Authenticator
    {
        private IdentityService _identityService;

        public IdentityService getIdentityService()
        {
            return _identityService;
        }

        @Override
        public void setConfiguration(Configuration configuration)
        {
            _identityService = configuration.getIdentityService();
        }

        @Override
        public String getAuthenticationType()
        {
            return getClass().getSimpleName();
        }

        @Override
        public AuthenticationState validateRequest(Request request, Response response, Callback callback) throws ServerAuthException
        {
            return null;
        }
    }
}

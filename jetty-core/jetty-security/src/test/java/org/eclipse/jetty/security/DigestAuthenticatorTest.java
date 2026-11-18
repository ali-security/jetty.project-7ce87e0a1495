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

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.jetty.security.authentication.DigestAuthenticator;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.session.SessionHandler;
import org.eclipse.jetty.util.TypeUtil;
import org.eclipse.jetty.util.security.Password;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class DigestAuthenticatorTest
{
    private static final String REALM = "TestRealm";
    private static final String PATH = "/ctx/any/user";
    private static final String CNONCE = "1234567890";

    // A password made of characters that cannot be represented in ISO-8859-1.
    // @checkstyle-disable-check : AvoidEscapedUnicodeCharactersCheck
    private static final String UNICODE_PASSWORD = "我爱Java!密码123★";
    // A different password that, once lossily encoded with ISO-8859-1, produces
    // exactly the same bytes as UNICODE_PASSWORD: every character that ISO-8859-1
    // cannot represent is silently replaced by '?'.
    private static final String LOSSY_GUESS = "??Java!??123?";

    private Server _server;
    private LocalConnector _connector;
    private DigestAuthenticator _authenticator;

    @BeforeEach
    public void configureServer() throws Exception
    {
        _server = new Server();

        HttpConnectionFactory http = new HttpConnectionFactory();
        _connector = new LocalConnector(_server, http);
        _connector.setIdleTimeout(300000);
        _server.addConnector(_connector);

        ContextHandler contextHandler = new ContextHandler();
        contextHandler.setContextPath("/ctx");
        _server.setHandler(contextHandler);

        SessionHandler sessionHandler = new SessionHandler();
        contextHandler.setHandler(sessionHandler);

        TestLoginService loginService = new TestLoginService(REALM);
        loginService.putUser("user", new Password("password"), new String[]{"user"});
        loginService.putUser("unicode", new Password(UNICODE_PASSWORD), new String[]{"user"});

        SecurityHandler.PathMapped securityHandler = new SecurityHandler.PathMapped();
        sessionHandler.setHandler(securityHandler);
        securityHandler.setLoginService(loginService);
        _authenticator = new DigestAuthenticator();
        securityHandler.setAuthenticator(_authenticator);
        securityHandler.put("/any/*", Constraint.ANY_USER);
        securityHandler.setHandler(new AuthenticationTestHandler());

        _server.start();
    }

    @AfterEach
    public void stopServer() throws Exception
    {
        if (_server.isRunning())
        {
            _server.stop();
            _server.join();
        }
    }

    @Test
    public void testDigest() throws Exception
    {
        String challenge = challenge();
        String nonce = parameter(challenge, "nonce");
        String opaque = parameter(challenge, "opaque");
        assertNotNull(nonce);

        // Wrong password is rejected.
        String response = request(authorization("user", "wrong", nonce, opaque, "00000001", UTF_8));
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        assertThat(response, not(containsString("is OK")));

        // Right password is accepted.
        response = request(authorization("user", "password", nonce, opaque, "00000002", UTF_8));
        assertThat(response, containsString("HTTP/1.1 200 OK"));
        assertThat(response, containsString("user is OK"));

        // Replaying the same nonce count is rejected.
        response = request(authorization("user", "password", nonce, opaque, "00000002", UTF_8));
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        assertThat(response, not(containsString("is OK")));
    }

    @Test
    public void testChallengeSpecifiesUtf8Charset() throws Exception
    {
        // The credentials are hashed with UTF-8, and the challenge must say so,
        // so that clients do not fall back to the lossy ISO-8859-1 of RFC 2617.
        String challenge = challenge();
        assertThat(challenge, containsString("charset=UTF-8"));
        assertThat(challenge, containsString("realm=\"" + REALM + "\""));
        assertThat(challenge, containsString("qop=\"auth\""));
        assertEquals("SHA-256", _authenticator.getAlgorithm());
        assertThat(challenge, containsString("algorithm=SHA-256"));
    }

    @Test
    public void testNonLatin1PasswordAuthenticates() throws Exception
    {
        String challenge = challenge();
        String nonce = parameter(challenge, "nonce");
        String opaque = parameter(challenge, "opaque");
        assertNotNull(nonce);

        // A password that ISO-8859-1 cannot represent must authenticate
        // when the client hashes the credentials with UTF-8.
        String response = request(authorization("unicode", UNICODE_PASSWORD, nonce, opaque, "00000001", UTF_8));
        assertThat(response, containsString("HTTP/1.1 200 OK"));
        assertThat(response, containsString("unicode is OK"));
    }

    @Test
    public void testLossyLatin1PasswordCollisionIsRejected() throws Exception
    {
        // The exploit precondition: the guessed password differs from the real
        // one, yet the two are indistinguishable once encoded with ISO-8859-1.
        assertNotEquals(UNICODE_PASSWORD, LOSSY_GUESS);
        assertArrayEquals(UNICODE_PASSWORD.getBytes(ISO_8859_1), LOSSY_GUESS.getBytes(ISO_8859_1));

        String challenge = challenge();
        String nonce = parameter(challenge, "nonce");
        String opaque = parameter(challenge, "opaque");
        assertNotNull(nonce);

        // The attacker knows only the collapsed password and uses a lossy
        // ISO-8859-1 client.
        String response = request(authorization("unicode", LOSSY_GUESS, nonce, opaque, "00000001", ISO_8859_1));
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        assertThat(response, not(containsString("is OK")));

        // The same collapsed password, hashed with UTF-8; the guess is all ASCII
        // so its UTF-8 bytes are the ISO-8859-1 bytes of the real password.
        response = request(authorization("unicode", LOSSY_GUESS, nonce, opaque, "00000002", UTF_8));
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        assertThat(response, not(containsString("is OK")));

        // The real password lossily hashed with ISO-8859-1 must not be accepted
        // either, otherwise the collapsed form remains a valid credential.
        response = request(authorization("unicode", UNICODE_PASSWORD, nonce, opaque, "00000003", ISO_8859_1));
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        assertThat(response, not(containsString("is OK")));
    }

    private String challenge() throws Exception
    {
        String response = _connector.getResponse("GET " + PATH + " HTTP/1.0\r\n\r\n");
        assertThat(response, containsString("HTTP/1.1 401 Unauthorized"));
        return response;
    }

    private String request(String authorization) throws Exception
    {
        return _connector.getResponse("GET %s HTTP/1.0\r\nAuthorization: %s\r\n\r\n".formatted(PATH, authorization));
    }

    private static String parameter(String challenge, String name)
    {
        Matcher matcher = Pattern.compile(name + "=\"([^\"]*)\"").matcher(challenge);
        return matcher.find() ? matcher.group(1) : null;
    }

    private String authorization(String username, String password, String nonce, String opaque, String nc, Charset charset) throws Exception
    {
        // Read the algorithm back from the authenticator so that this
        // client-side digest follows the server-side default.
        String algorithm = _authenticator.getAlgorithm();
        MessageDigest md = MessageDigest.getInstance(algorithm);

        byte[] ha1 = md.digest((username + ":" + REALM + ":" + password).getBytes(charset));
        byte[] ha2 = md.digest(("GET:" + PATH).getBytes(charset));
        String rsp = TypeUtil.toString(ha1, 16) + ":" + nonce + ":" + nc +
            ":" + CNONCE + ":auth:" + TypeUtil.toString(ha2, 16);
        String response = TypeUtil.toString(md.digest(rsp.getBytes(charset)), 16);

        StringBuilder authorization = new StringBuilder("Digest");
        authorization.append(" username=\"").append(username).append("\"");
        authorization.append(", realm=\"").append(REALM).append("\"");
        authorization.append(", nonce=\"").append(nonce).append("\"");
        if (opaque != null)
            authorization.append(", opaque=\"").append(opaque).append("\"");
        authorization.append(", uri=\"").append(PATH).append("\"");
        authorization.append(", algorithm=").append(algorithm);
        authorization.append(", qop=auth");
        authorization.append(", nc=").append(nc);
        authorization.append(", cnonce=\"").append(CNONCE).append("\"");
        authorization.append(", response=\"").append(response).append("\"");
        return authorization.toString();
    }
}

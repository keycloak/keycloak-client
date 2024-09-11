/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.client.testsuite.framework;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.testcontainers.Testcontainers;

/**
 * <p>Simple extension to start a HTTP server for pairwise redirect URIs responses.
 * It runs in port 8280 and fixes the response. The sectorIdentifierUri in the
 * pairwise mapper should be <em>http://host.testcontainers.internal:8280</em>.
 * </p>
 *
 * @author rmartinc
 */
public class PairwiseHttpServerExtension implements AfterAllCallback, BeforeAllCallback {

    public static final int HTTP_PORT = 8280;
    public static final String PAIRWISE_RESPONSE = "[\"http://localhost/resource-server-test\"]";
    public static final String HTTP_URL = "http://host.testcontainers.internal:" + HTTP_PORT;

    private HttpServer server;

    private class MyHandler implements HttpHandler {

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // just return the same data received, headers inclusive
            if ("GET".equals(exchange.getRequestMethod())) {
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                byte[] data = PAIRWISE_RESPONSE.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(HttpURLConnection.HTTP_OK, data.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(data);
                }
            } else {
                exchange.sendResponseHeaders(400, 0);
            }
        }
    }

    @Override
    public void afterAll(ExtensionContext ec) throws Exception {
        server.stop(0);
    }

    @Override
    public void beforeAll(ExtensionContext ec) throws Exception {
        server = HttpServer.create(new InetSocketAddress(HTTP_PORT), 0);
        server.createContext("/", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
        Testcontainers.exposeHostPorts(HTTP_PORT);
    }

}

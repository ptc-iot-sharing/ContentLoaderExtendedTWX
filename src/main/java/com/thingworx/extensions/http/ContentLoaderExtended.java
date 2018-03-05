package com.thingworx.extensions.http;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.utils.HttpUtilities;
import com.thingworx.common.utils.JSONUtilities;
import com.thingworx.metadata.annotations.ThingworxServiceDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceParameter;
import com.thingworx.metadata.annotations.ThingworxServiceResult;
import com.thingworx.resources.Resource;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.client.AuthCache;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

public class ContentLoaderExtended extends Resource {
    private static final Logger _logger = LoggerFactory.getLogger(ContentLoaderExtended.class);

    public static void enablePremptiveAuthentication(HttpClientContext context, String rawURL) throws MalformedURLException {
        URL url = new URL(rawURL);
        HttpHost targetHost = new HttpHost(url.getHost(), url.getPort(), url.getProtocol());
        AuthCache authCache = new BasicAuthCache();
        BasicScheme basicAuth = new BasicScheme();
        authCache.put(targetHost, basicAuth);
        context.setAuthCache(authCache);
    }

    @ThingworxServiceDefinition(
            name = "PatchJSON",
            description = "Load JSON content from a URL via HTTP PATCH",
            category = "JSON"
    )
    @ThingworxServiceResult(
            name = "result",
            description = "Loaded content as JSON Object",
            baseType = "JSON"
    )
    public JSONObject PatchJSON(
            @ThingworxServiceParameter
                    (name = "url", description = "URL to load", baseType = "STRING") String url,
            @ThingworxServiceParameter
                    (name = "content", description = "Posted content as JSON object", baseType = "STRING") String content,
            @ThingworxServiceParameter
                    (name = "username", description = "Optional user name credential", baseType = "STRING") String username,
            @ThingworxServiceParameter
                    (name = "password", description = "Optional password credential", baseType = "STRING") String password,
            @ThingworxServiceParameter
                    (name = "headers", description = "Optional HTTP headers", baseType = "JSON") JSONObject headers,
            @ThingworxServiceParameter
                    (name = "ignoreSSLErrors", description = "Ignore SSL Certificate Errors", baseType = "BOOLEAN") Boolean ignoreSSLErrors,
            @ThingworxServiceParameter
                    (name = "withCookies", description = "Include cookies in response", baseType = "BOOLEAN", aspects = {"defaultValue:false"}) Boolean withCookies,
            @ThingworxServiceParameter
                    (name = "timeout", description = "Optional timeout in seconds", baseType = "NUMBER", aspects = {"defaultValue:60"}) Double timeout,
            @ThingworxServiceParameter
                    (name = "useNTLM", description = "Use NTLM Authentication", baseType = "BOOLEAN", aspects = {"defaultValue:false"}) Boolean useNTLM,
            @ThingworxServiceParameter
                    (name = "workstation", description = "Auth workstation", baseType = "STRING", aspects = {"defaultValue:"}) String workstation,
            @ThingworxServiceParameter
                    (name = "domain", description = "Auth domain", baseType = "STRING", aspects = {"defaultValue:"}) String domain,
            @ThingworxServiceParameter
                    (name = "useProxy", description = "Use Proxy server", baseType = "BOOLEAN", aspects = {"defaultValue:false"}) Boolean useProxy,
            @ThingworxServiceParameter
                    (name = "proxyHost", description = "Proxy host", baseType = "STRING", aspects = {"defaultValue:"}) String proxyHost,
            @ThingworxServiceParameter
                    (name = "proxyPort", description = "Proxy port", baseType = "INTEGER", aspects = {"defaultValue:8080"}) Integer proxyPort,
            @ThingworxServiceParameter
                    (name = "proxyScheme", description = "Proxy scheme", baseType = "STRING", aspects = {"defaultValue:http"}) String proxyScheme)
            throws Exception {
        JSONObject json;
        HttpPatch patch = new HttpPatch(url);

        try (CloseableHttpClient client = HttpUtilities.createHttpClient(username, password, ignoreSSLErrors, timeout,
                useNTLM, workstation, domain, useProxy, proxyHost, proxyPort, proxyScheme)) {
            String cookieResult;
            if (headers != null) {
                if (headers.length() == 0) {
                    _logger.error("Error constructing headers JSONObject");
                }
                Iterator iHeaders = headers.keys();

                while (iHeaders.hasNext()) {
                    String headerName = (String) iHeaders.next();
                    cookieResult = headers.get(headerName).toString();
                    patch.addHeader(headerName, cookieResult);
                }
            }

            patch.addHeader("Accept", "application/json");
            if (content != null) {
                patch.setEntity(new StringEntity(content, ContentType.create("application/json", RESTAPIConstants.getUTF8Charset())));
            }

            HttpClientContext context = HttpClientContext.create();
            enablePremptiveAuthentication(context, url);

            try (CloseableHttpResponse response = client.execute(patch, context)) {
                if (response.getStatusLine().getStatusCode() == RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()) {
                    json = new JSONObject();
                } else {
                    cookieResult = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8.name());
                    json = JSONUtilities.readJSON(cookieResult);
                }

                if (headers != null) {
                    json.put("headers", headers);
                } else {
                    json.put("headers", "");
                }

            }
        } finally {
            try {
                patch.reset();
            } catch (Exception var32) {
                _logger.info("PatchJSON ERROR, exception caught resetting HttpPatch: {}", var32.getMessage());
            }


        }

        return json;
    }
}


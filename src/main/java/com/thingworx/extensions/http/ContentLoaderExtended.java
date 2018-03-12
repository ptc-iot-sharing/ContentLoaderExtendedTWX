package com.thingworx.extensions.http;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.utils.HttpUtilities;
import com.thingworx.common.utils.JSONUtilities;
import com.thingworx.common.utils.StreamUtilities;
import com.thingworx.common.utils.StringUtilities;
import com.thingworx.entities.utils.EntityUtilities;
import com.thingworx.metadata.annotations.ThingworxServiceDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceParameter;
import com.thingworx.metadata.annotations.ThingworxServiceResult;
import com.thingworx.relationships.RelationshipTypes;
import com.thingworx.resources.Resource;
import com.thingworx.things.repository.FileRepositoryThing;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
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

    @ThingworxServiceDefinition(
            name = "GetString",
            description = "Load JSON content from a URL via HTTP PATCH",
            category = "STRING"
    )
    @ThingworxServiceResult(
            name = "result",
            description = "The resulting data as string",
            baseType = "STRING"
    )
    public String GetString(
            @ThingworxServiceParameter
                    (name = "url", description = "URL to load", baseType = "STRING") String url,
            @ThingworxServiceParameter
                    (name = "username", description = "Optional user name credential", baseType = "STRING") String username,
            @ThingworxServiceParameter
                    (name = "password", description = "Optional password credential", baseType = "STRING") String password,
            @ThingworxServiceParameter
                    (name = "headers", description = "Optional HTTP headers", baseType = "JSON") JSONObject headers,
            @ThingworxServiceParameter
                    (name = "ignoreSSLErrors", description = "Ignore SSL Certificate Errors", baseType = "BOOLEAN") Boolean ignoreSSLErrors,
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
                    (name = "proxyScheme", description = "Proxy scheme", baseType = "STRING", aspects = {"defaultValue:http"}) String proxyScheme,
            @ThingworxServiceParameter
                    (name = "fileRepository", description = "FileRepository where the client keys are", baseType = "THINGNAME", aspects = {"thingTemplate:FileRepository"}) String fileRepository,
            @ThingworxServiceParameter
                    (name = "certFilePath", description = "Path to the p12 cert file", baseType = "STRING", aspects = {"defaultvalue:cert.p12"}) String certFilePath,
            @ThingworxServiceParameter
                    (name = "certFilePassword", description = "Password of the p12 file", baseType = "STRING", aspects = {"defaultvalue:changeit"}) String certFilePassword
    )
            throws Exception {
        String result;
        HttpGet httpGet = new HttpGet(url);
        ByteArrayInputStream stream = null;

        // look if the certFile parth and the repository is enabled. If yes, then attempt to load the cert
        if (!StringUtilities.isNullOrEmpty(fileRepository) && !StringUtilities.isNullOrEmpty(certFilePath)) {
            FileRepositoryThing fileRepo = (FileRepositoryThing)
                    EntityUtilities.findEntity(fileRepository, RelationshipTypes.ThingworxRelationshipTypes.Thing);
            stream = new ByteArrayInputStream(fileRepo.LoadBinary(certFilePath));
        }

        try (CloseableHttpClient client = createHttpClient(username, password, ignoreSSLErrors, timeout,
                useNTLM, workstation, domain, useProxy, proxyHost, proxyPort, proxyScheme, stream, certFilePassword)) {
            if (headers != null) {
                if (headers.length() == 0) {
                    _logger.error("Error constructing headers JSONObject");
                }
                Iterator iHeaders = headers.keys();

                while (iHeaders.hasNext()) {
                    String headerName = (String) iHeaders.next();
                    httpGet.addHeader(headerName, headers.get(headerName).toString());
                }
            }

            HttpClientContext context = HttpClientContext.create();
            enablePremptiveAuthentication(context, url);

            try (CloseableHttpResponse response = client.execute(httpGet, context)) {
                if (response.getStatusLine().getStatusCode() == RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()) {
                    result = "";
                } else {
                    result = IOUtils.toString(response.getEntity().getContent(), StandardCharsets.UTF_8.name());
                }

            }
        } finally {
            try {
                httpGet.reset();
            } catch (Exception var32) {
                _logger.info("GetString ERROR, exception caught resetting httpGet: {}", var32.getMessage());
            }

        }

        return result;
    }

    @ThingworxServiceDefinition(
            name = "GetBlob",
            description = "Load JSON content from a URL via HTTP PATCH",
            category = "BLOB"
    )
    @ThingworxServiceResult(
            name = "result",
            description = "The resulting data as string",
            baseType = "BLOB"
    )
    public byte[] GetBlob(
            @ThingworxServiceParameter
                    (name = "url", description = "URL to load", baseType = "STRING") String url,
            @ThingworxServiceParameter
                    (name = "username", description = "Optional user name credential", baseType = "STRING") String username,
            @ThingworxServiceParameter
                    (name = "password", description = "Optional password credential", baseType = "STRING") String password,
            @ThingworxServiceParameter
                    (name = "headers", description = "Optional HTTP headers", baseType = "JSON") JSONObject headers,
            @ThingworxServiceParameter
                    (name = "ignoreSSLErrors", description = "Ignore SSL Certificate Errors", baseType = "BOOLEAN") Boolean ignoreSSLErrors,
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
                    (name = "proxyScheme", description = "Proxy scheme", baseType = "STRING", aspects = {"defaultValue:http"}) String proxyScheme,
            @ThingworxServiceParameter
                    (name = "fileRepository", description = "FileRepository where the client keys are", baseType = "THINGNAME", aspects = {"thingTemplate:FileRepository"}) String fileRepository,
            @ThingworxServiceParameter
                    (name = "certFilePath", description = "Path to the p12 cert file", baseType = "STRING", aspects = {"defaultvalue:cert.p12"}) String certFilePath,
            @ThingworxServiceParameter
                    (name = "certFilePassword", description = "Password of the p12 file", baseType = "STRING", aspects = {"defaultvalue:changeit"}) String certFilePassword
    )
            throws Exception {
        byte[] result = new byte[0];
        HttpGet httpGet = new HttpGet(url);
        ByteArrayInputStream stream = null;

        // look if the certFile parth and the repository is enabled. If yes, then attempt to load the cert
        if (!StringUtilities.isNullOrEmpty(fileRepository) && !StringUtilities.isNullOrEmpty(certFilePath)) {
            FileRepositoryThing fileRepo = (FileRepositoryThing)
                    EntityUtilities.findEntity(fileRepository, RelationshipTypes.ThingworxRelationshipTypes.Thing);
            stream = new ByteArrayInputStream(fileRepo.LoadBinary(certFilePath));
        }

        try (CloseableHttpClient client = createHttpClient(username, password, ignoreSSLErrors, timeout,
                useNTLM, workstation, domain, useProxy, proxyHost, proxyPort, proxyScheme, stream, certFilePassword)) {
            if (headers != null) {
                if (headers.length() == 0) {
                    _logger.error("Error constructing headers JSONObject");
                }
                Iterator iHeaders = headers.keys();

                while (iHeaders.hasNext()) {
                    String headerName = (String) iHeaders.next();
                    httpGet.addHeader(headerName, headers.get(headerName).toString());
                }
            }

            HttpClientContext context = HttpClientContext.create();
            enablePremptiveAuthentication(context, url);

            try (CloseableHttpResponse response = client.execute(httpGet, context)) {
                if (response.getStatusLine().getStatusCode() == RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()) {
                } else {
                    result = StreamUtilities.readStreamToByteArray(response.getEntity().getContent());
                }

            }
        } finally {
            try {
                httpGet.reset();
            } catch (Exception var32) {
                _logger.info("GetBlob ERROR, exception caught resetting httpGet: {}", var32.getMessage());
            }

        }

        return result;
    }

    public CloseableHttpClient createHttpClient(String username, String password, Boolean ignoreSSLErrors,
                                                Double timeout, Boolean useNTLM, String workstation, String domain,
                                                Boolean useProxy, String proxyHost, Integer proxyPort,
                                                String proxyScheme, InputStream certStream, String certPass) {
        try {
            if (timeout == null) {
                timeout = 60.0D;
            }

            if (ignoreSSLErrors == null) {
                ignoreSSLErrors = false;
            }

            if (proxyScheme == null) {
                proxyScheme = "http";
            }

            int httpTimeout = timeout.intValue() * 1000;
            HttpClientBuilder clientBuilder = HttpClientBuilder.create();
            RequestConfig.Builder requestConfigBuilder = RequestConfig.custom().setConnectTimeout(httpTimeout).setSocketTimeout(httpTimeout);
            if (useProxy == null) {
                useProxy = false;
            }

            if (useProxy && StringUtilities.isNonEmpty(proxyHost) && proxyPort != null) {
                HttpHost proxy = new HttpHost(proxyHost, proxyPort, proxyScheme);
                requestConfigBuilder.setProxy(proxy);
            }

            RequestConfig requestConfig = requestConfigBuilder.build();
            clientBuilder.setDefaultRequestConfig(requestConfig);
            if (ignoreSSLErrors) {
                SSLContextBuilder sslContextBuilder = SSLContexts.custom().
                        loadTrustMaterial(null, new TrustSelfSignedStrategy());
                if (certStream != null) {
                    // Client keystore
                    KeyStore cks = KeyStore.getInstance("PKCS12");
                    cks.load(certStream, certPass.toCharArray());
                    sslContextBuilder.loadKeyMaterial(cks, certPass.toCharArray());
                }
                SSLContext sslContext = sslContextBuilder.build();
                SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(sslContext, NoopHostnameVerifier.INSTANCE);
                clientBuilder.setSSLSocketFactory(sslConnectionFactory);
            }

            if (username != null && password != null) {
                CredentialsProvider credsProvider = new BasicCredentialsProvider();
                if (useNTLM != null && useNTLM) {
                    if (workstation == null) {
                        workstation = "";
                    }

                    if (domain == null) {
                        domain = "";
                    }

                    credsProvider.setCredentials(AuthScope.ANY, new NTCredentials(username, password, workstation, domain));
                } else {
                    credsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
                }

                clientBuilder.setDefaultCredentialsProvider(credsProvider);
            }

            return clientBuilder.build();
        } catch (Exception var18) {
            throw new RuntimeException(var18);
        }
    }
}


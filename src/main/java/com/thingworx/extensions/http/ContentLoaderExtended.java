package com.thingworx.extensions.http;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.exceptions.InvalidRequestException;
import com.thingworx.common.utils.HttpUtilities;
import com.thingworx.common.utils.JSONUtilities;
import com.thingworx.common.utils.StreamUtilities;
import com.thingworx.datashape.DataShape;
import com.thingworx.entities.utils.EntityUtilities;
import com.thingworx.entities.utils.ThingUtilities;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxServiceDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceParameter;
import com.thingworx.metadata.annotations.ThingworxServiceResult;
import com.thingworx.relationships.RelationshipTypes;
import com.thingworx.resources.Resource;
import com.thingworx.things.repository.FileRepositoryThing;
import com.thingworx.types.InfoTable;
import com.thingworx.types.collections.ValueCollection;
import com.thingworx.types.primitives.StringPrimitive;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.StatusLine;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;

public class ContentLoaderExtended extends Resource {
  private static final Logger _logger = LogUtilities
    .getInstance()
    .getApplicationLogger(ContentLoaderExtended.class);

  public static void enablePremptiveAuthentication(
    HttpClientContext context,
    String rawURL
  )
    throws MalformedURLException {
    URL url = new URL(rawURL);
    HttpHost targetHost = new HttpHost(
      url.getHost(),
      url.getPort(),
      url.getProtocol()
    );
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
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "content",
      description = "Posted content as JSON object",
      baseType = "STRING"
    ) String content,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "withCookies",
      description = "Include cookies in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean withCookies,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "includeStatusCode",
      description = "Include the response code in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean includeStatusCode
  )
    throws Exception {
    JSONObject json;
    HttpPatch patch = new HttpPatch(url);

    try (
      CloseableHttpClient client = HttpUtilities.createHttpClient(
        username,
        password,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme
      )
    ) {
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
        patch.setEntity(
          new StringEntity(
            content,
            ContentType.create(
              "application/json",
              RESTAPIConstants.getUTF8Charset()
            )
          )
        );
      }

      HttpClientContext context = HttpClientContext.create();
      enablePremptiveAuthentication(context, url);

      try (CloseableHttpResponse response = client.execute(patch, context)) {
        if (
          response.getStatusLine().getStatusCode() ==
          RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()
        ) {
          json = new JSONObject();
        } else {
          cookieResult =
            IOUtils.toString(
              response.getEntity().getContent(),
              StandardCharsets.UTF_8.name()
            );
          json = JSONUtilities.readJSON(cookieResult);
        }

        if (headers != null) {
          json.put("headers", headers);
        } else {
          json.put("headers", "");
        }
        addResponseStatus(includeStatusCode, json, response);
      }
    } finally {
      try {
        patch.reset();
      } catch (Exception ex) {
        _logger.info(
          "PatchJSON ERROR, exception caught resetting HttpPatch: {}",
          ex.getMessage()
        );
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
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "fileRepository",
      description = "FileRepository where the client keys are",
      baseType = "THINGNAME",
      aspects = { "thingTemplate:FileRepository" }
    ) String fileRepository,
    @ThingworxServiceParameter(
      name = "certFilePath",
      description = "Path to the p12 cert file",
      baseType = "STRING",
      aspects = { "defaultvalue:cert.p12" }
    ) String certFilePath,
    @ThingworxServiceParameter(
      name = "certFilePassword",
      description = "Password of the p12 file",
      baseType = "STRING",
      aspects = { "defaultvalue:changeit" }
    ) String certFilePassword
  )
    throws Exception {
    String result;
    HttpGet httpGet = new HttpGet(url);
    ByteArrayInputStream stream = null;

    // look if the certFile parth and the repository is enabled. If yes, then attempt to load the cert
    if (
      !StringUtilities.isNullOrEmpty(fileRepository) &&
      !StringUtilities.isNullOrEmpty(certFilePath)
    ) {
      FileRepositoryThing fileRepo = (FileRepositoryThing) EntityUtilities.findEntity(
        fileRepository,
        RelationshipTypes.ThingworxRelationshipTypes.Thing
      );
      stream = new ByteArrayInputStream(fileRepo.LoadBinary(certFilePath));
    }

    try (
      CloseableHttpClient client = createHttpClient(
        username,
        password,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        stream,
        certFilePassword
      )
    ) {
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
        if (
          response.getStatusLine().getStatusCode() ==
          RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()
        ) {
          result = "";
        } else {
          result =
            IOUtils.toString(
              response.getEntity().getContent(),
              StandardCharsets.UTF_8.name()
            );
        }
      }
    } finally {
      try {
        httpGet.reset();
      } catch (Exception ex) {
        _logger.info(
          "GetString ERROR, exception caught resetting httpGet: {}",
          ex.getMessage()
        );
      }
    }

    return result;
  }

  @ThingworxServiceDefinition(
    name = "GetBlob",
    description = "Load BLOB using GET from a server with client certs",
    category = "BLOB"
  )
  @ThingworxServiceResult(
    name = "result",
    description = "The resulting data as string",
    baseType = "BLOB"
  )
  public byte[] GetBlob(
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "fileRepository",
      description = "FileRepository where the client keys are",
      baseType = "THINGNAME",
      aspects = { "thingTemplate:FileRepository" }
    ) String fileRepository,
    @ThingworxServiceParameter(
      name = "certFilePath",
      description = "Path to the p12 cert file",
      baseType = "STRING",
      aspects = { "defaultvalue:cert.p12" }
    ) String certFilePath,
    @ThingworxServiceParameter(
      name = "certFilePassword",
      description = "Password of the p12 file",
      baseType = "STRING",
      aspects = { "defaultvalue:changeit" }
    ) String certFilePassword,
    @ThingworxServiceParameter(
      name = "resultFileRepository",
      description = "File repository where to store the result",
      baseType = "THINGNAME",
      aspects = { "thingTemplate:FileRepository" }
    ) String resultFileRepository,
    @ThingworxServiceParameter(
      name = "resultFilePath",
      description = "Path in the result file repository",
      baseType = "STRING",
      aspects = { "defaultvalue:result.data" }
    ) String resultFilePath
  )
    throws Exception {
    byte[] result = new byte[0];
    HttpGet httpGet = new HttpGet(url);
    ByteArrayInputStream stream = null;

    // look if the certFile parth and the repository is enabled. If yes, then attempt to load the cert
    if (
      !StringUtilities.isNullOrEmpty(fileRepository) &&
      !StringUtilities.isNullOrEmpty(certFilePath)
    ) {
      FileRepositoryThing fileRepo = (FileRepositoryThing) EntityUtilities.findEntity(
        fileRepository,
        RelationshipTypes.ThingworxRelationshipTypes.Thing
      );
      stream = new ByteArrayInputStream(fileRepo.LoadBinary(certFilePath));
      _logger.info("Read certificate from file");
    }

    try (
      CloseableHttpClient client = createHttpClient(
        username,
        password,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        stream,
        certFilePassword
      )
    ) {
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
        if (
          response.getStatusLine().getStatusCode() ==
          RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()
        ) {} else {
          result =
            StreamUtilities.readStreamToByteArray(
              response.getEntity().getContent()
            );
        }
        _logger.info(
          "Read executed GET request and read " +
          result.length +
          " out of the stream"
        );
      }
      if (
        !StringUtilities.isNullOrEmpty(resultFilePath) &&
        !StringUtilities.isNullOrEmpty(resultFileRepository)
      ) {
        FileRepositoryThing resultFileRepo = (FileRepositoryThing) EntityUtilities.findEntity(
          resultFileRepository,
          RelationshipTypes.ThingworxRelationshipTypes.Thing
        );
        resultFileRepo.SaveBinary(resultFilePath, result);
        _logger.info("Written the result to file");
      }
    } finally {
      try {
        httpGet.reset();
      } catch (Exception ex) {
        _logger.info(
          "GetBlob ERROR, exception caught resetting httpGet: {}",
          ex.getMessage()
        );
      }
    }

    return result;
  }

  @ThingworxServiceDefinition(
    name = "GetJSON",
    description = "Get json content from a URL",
    category = "JSON"
  )
  @ThingworxServiceResult(
    name = "result",
    description = "Loaded content as text content",
    baseType = "JSON"
  )
  public JSONObject GetJSON(
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "withCookies",
      description = "Include cookies in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean withCookies,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "includeStatusCode",
      description = "Include the response code in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean includeStatusCode
  )
    throws Exception {
    CloseableHttpClient client = createHttpClient(
      username,
      password,
      ignoreSSLErrors,
      timeout,
      useNTLM,
      workstation,
      domain,
      useProxy,
      proxyHost,
      proxyPort,
      proxyScheme,
      null,
      null
    );
    HttpGet get = new HttpGet(url);
    JSONObject json = null;

    try {
      String cookieResult;
      if (headers != null) {
        Iterator iHeaders = headers.keys();

        while (iHeaders.hasNext()) {
          String headerName = (String) iHeaders.next();
          cookieResult = headers.get(headerName).toString();
          get.addHeader(headerName, cookieResult);
        }
      }

      get.addHeader("Accept", "application/json");
      HttpClientContext context = HttpClientContext.create();
      context.setCookieStore(new BasicCookieStore());

      enablePremptiveAuthentication(context, url);

      try (CloseableHttpResponse response = client.execute(get, context)) {
        if (
          response.getStatusLine().getStatusCode() ==
          RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()
        ) {
          json = new JSONObject();
        } else {
          cookieResult =
            StringUtilities.readFromStream(
              response.getEntity().getContent(),
              true
            );
          json = JSONUtilities.readJSON(cookieResult);
        }

        if (withCookies) {
          cookieResult = cookiesToString(context.getCookieStore().getCookies());
          json.put("_cookies", cookieResult);
        }

        if (headers != null) {
          json.put("headers", headers);
        } else {
          json.put("headers", "");
        }
        addResponseStatus(includeStatusCode, json, response);
      }
    } finally {
      try {
        get.reset();
      } catch (Exception ex) {
        _logger.info(
          "LoadJSON ERROR, exception caught resetting HttpGet: {}",
          ex.getMessage()
        );
      }

      client.close();
    }

    return json;
  }

  @ThingworxServiceDefinition(
    name = "PostJSON",
    description = "Load JSON content from a URL via HTTP POST",
    category = "JSON"
  )
  @ThingworxServiceResult(
    name = "result",
    description = "Loaded content as JSON Object",
    baseType = "JSON"
  )
  public JSONObject PostJSON(
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "content",
      description = "Posted content as JSON object",
      baseType = "JSON"
    ) JSONObject content,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "withCookies",
      description = "Include cookies in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean withCookies,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "includeStatusCode",
      description = "Include the response code in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean includeStatusCode
  )
    throws Exception {
    JSONObject json = null;

    try (
      CloseableHttpClient client = createHttpClient(
        username,
        password,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        null,
        null
      )
    ) {
      HttpPost post = new HttpPost(url);
      String cookieResult;
      if (headers != null) {
        Iterator iHeaders = headers.keys();

        while (iHeaders.hasNext()) {
          String headerName = (String) iHeaders.next();
          cookieResult = headers.get(headerName).toString();
          post.addHeader(headerName, cookieResult);
        }
      }

      post.addHeader("Accept", "application/json");
      if (content != null) {
        post.setEntity(
          new StringEntity(
            JSONUtilities.writeJSON(content),
            ContentType.create(
              "application/json",
              RESTAPIConstants.getUTF8Charset()
            )
          )
        );
      }

      HttpClientContext context = HttpClientContext.create();
      context.setCookieStore(new BasicCookieStore());

      enablePremptiveAuthentication(context, url);

      try (CloseableHttpResponse response = client.execute(post, context)) {
        if (
          response.getStatusLine().getStatusCode() ==
          RESTAPIConstants.StatusCode.STATUS_NO_CONTENT.httpCode()
        ) {
          json = new JSONObject();
        } else {
          cookieResult =
            StringUtilities.readFromStream(
              response.getEntity().getContent(),
              true
            );
          json = JSONUtilities.readJSON(cookieResult);
        }

        if (withCookies) {
          cookieResult = cookiesToString(context.getCookieStore().getCookies());
          json.put("_cookies", cookieResult);
        }
        addResponseStatus(includeStatusCode, json, response);
        if (headers != null) {
          json.put("headers", headers);
        } else {
          json.put("headers", "");
        }
      }
    }

    return json;
  }

  @ThingworxServiceDefinition(
    name = "PostMultipart",
    description = "Multipart data upload from Thingworx to and external target via HTTP POST",
    category = "Multipart"
  )
  @ThingworxServiceResult(
    name = "result",
    description = "Response as JSON Object",
    baseType = "JSON"
  )
  public JSONObject PostMultipart(
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "repository",
      description = "Repository to get file from to upload",
      baseType = "STRING"
    ) String repository,
    @ThingworxServiceParameter(
      name = "pathOnRepository",
      description = "Path on repository to file",
      baseType = "STRING"
    ) String pathOnRepository,
    @ThingworxServiceParameter(
      name = "partsToSend",
      description = "Infotable where each field is a part to send",
      baseType = "INFOTABLE"
    ) InfoTable partsToSend,
    @ThingworxServiceParameter(
      name = "multipartFileName",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String multipartFileName,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "includeStatusCode",
      description = "Include the response code in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean includeStatusCode
  )
    throws Exception {
    ValueCollection vc = new ValueCollection();
    vc.put("repository", new StringPrimitive(repository));
    vc.put("pathOnRepository", new StringPrimitive(pathOnRepository));
    vc.put("multipartFileName", new StringPrimitive(multipartFileName));
    DataShape dataShapeReference =
      (
        (DataShape) EntityUtilities.findEntity(
          "MultipartFiles_DS",
          RelationshipTypes.ThingworxRelationshipTypes.DataShape
        )
      );
    InfoTable filesToSend = new InfoTable(dataShapeReference.getDataShape());
    filesToSend.addRow(vc);
    return this.PostMultipartMultipleFiles(
        url,
        partsToSend,
        filesToSend,
        username,
        password,
        headers,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        includeStatusCode
      );
  }

  @ThingworxServiceDefinition(
    name = "PostMultipartMultipleFiles",
    description = "Multipart data upload from Thingworx to and external target via HTTP POST with multiple files",
    category = "Multipart"
  )
  @ThingworxServiceResult(
    name = "result",
    description = "Response as JSON Object",
    baseType = "JSON"
  )
  public JSONObject PostMultipartMultipleFiles(
    @ThingworxServiceParameter(
      name = "url",
      description = "URL to load",
      baseType = "STRING"
    ) String url,
    @ThingworxServiceParameter(
      name = "partsToSend",
      description = "Infotable where each row is a multipart part to send",
      baseType = "INFOTABLE"
    ) InfoTable partsToSend,
    @ThingworxServiceParameter(
      name = "filesToSend",
      description = "Infotable where row field is a file that should be sent as part of the multipart request",
      baseType = "INFOTABLE"
    ) InfoTable filesToSend,
    @ThingworxServiceParameter(
      name = "username",
      description = "Optional user name credential",
      baseType = "STRING"
    ) String username,
    @ThingworxServiceParameter(
      name = "password",
      description = "Optional password credential",
      baseType = "STRING"
    ) String password,
    @ThingworxServiceParameter(
      name = "headers",
      description = "Optional HTTP headers",
      baseType = "JSON"
    ) JSONObject headers,
    @ThingworxServiceParameter(
      name = "ignoreSSLErrors",
      description = "Ignore SSL Certificate Errors",
      baseType = "BOOLEAN"
    ) Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(
      name = "timeout",
      description = "Optional timeout in seconds",
      baseType = "NUMBER",
      aspects = { "defaultValue:60" }
    ) Double timeout,
    @ThingworxServiceParameter(
      name = "useNTLM",
      description = "Use NTLM Authentication",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useNTLM,
    @ThingworxServiceParameter(
      name = "workstation",
      description = "Auth workstation",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String workstation,
    @ThingworxServiceParameter(
      name = "domain",
      description = "Auth domain",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String domain,
    @ThingworxServiceParameter(
      name = "useProxy",
      description = "Use Proxy server",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean useProxy,
    @ThingworxServiceParameter(
      name = "proxyHost",
      description = "Proxy host",
      baseType = "STRING",
      aspects = { "defaultValue:" }
    ) String proxyHost,
    @ThingworxServiceParameter(
      name = "proxyPort",
      description = "Proxy port",
      baseType = "INTEGER",
      aspects = { "defaultValue:8080" }
    ) Integer proxyPort,
    @ThingworxServiceParameter(
      name = "proxyScheme",
      description = "Proxy scheme",
      baseType = "STRING",
      aspects = { "defaultValue:http" }
    ) String proxyScheme,
    @ThingworxServiceParameter(
      name = "includeStatusCode",
      description = "Include the response code in response",
      baseType = "BOOLEAN",
      aspects = { "defaultValue:false" }
    ) Boolean includeStatusCode
  )
    throws Exception {
    FileRepositoryThing repoThing;
    FileInputStream inputStream;

    JSONObject result;
    if (StringUtilities.isNullOrEmpty(url)) {
      throw new InvalidRequestException(
        "URL parameter cannot be blank",
        RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
      );
    }

    for (ValueCollection row : filesToSend.getRows()) {
      if (
        !ArgumentValidator.checkBothNotSetOrBothSet(
          row.getStringValue("repository"),
          row.getStringValue("pathOnRepository")
        )
      ) {
        throw new InvalidRequestException(
          "Invalid repository or path",
          RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
        );
      }
    }

    if (partsToSend == null && filesToSend == null) {
      throw new InvalidRequestException(
        "Must have either filesToSend or partsToSend",
        RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
      );
    }

    MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
    if (partsToSend != null) {
      this.infoTableToMultipart(partsToSend, entityBuilder);
    }

    for (ValueCollection row : filesToSend.getRows()) {
      String repository = row.getStringValue("repository");
      String pathOnRepository = row.getStringValue("pathOnRepository");
      String multipartFileName = row.getStringValue("multipartFileName");

      if (
        !StringUtilities.isNullOrEmpty(repository) &&
        !StringUtilities.isNullOrEmpty(repository)
      ) {
        String fileName = FilenameUtils.getName(pathOnRepository);
        if (StringUtilities.isNullOrEmpty(fileName)) {
          throw new InvalidRequestException(
            "Filename could not be found in path: [" + pathOnRepository + "]",
            RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
          );
        }

        repoThing = (FileRepositoryThing) ThingUtilities.findThing(repository);
        if (repoThing == null) {
          throw new InvalidRequestException(
            "File Repository [" + repository + "] does not exist",
            RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
          );
        }

        try {
          inputStream = repoThing.openFileForRead(pathOnRepository);
          String mimeType = URLConnection.guessContentTypeFromName(fileName);
          ContentType contentType = mimeType != null
            ? ContentType.create(mimeType)
            : ContentType.APPLICATION_OCTET_STREAM;
          entityBuilder.addBinaryBody(
            multipartFileName,
            inputStream,
            contentType,
            fileName
          );
        } catch (Exception ex) {
          throw new InvalidRequestException(
            "File [" +
            fileName +
            "] in repository [" +
            repository +
            "] could not be opened for reading",
            RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST
          );
        }
      }
    }

    HttpEntity entity = entityBuilder.build();

    try (
      CloseableHttpClient client = createHttpClient(
        username,
        password,
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        null,
        null
      )
    ) {
      HttpPost post = new HttpPost(url);
      String stringResult;
      if (headers != null) {
        Iterator iHeaders = headers.keys();

        while (iHeaders.hasNext()) {
          String headerName = (String) iHeaders.next();
          stringResult = headers.get(headerName).toString();
          post.addHeader(headerName, stringResult);
        }
      }

      post.setEntity(entity);
      CloseableHttpResponse response = client.execute(post);
      Throwable exception = null;

      try {
        stringResult =
          StringUtilities.readFromStream(
            response.getEntity().getContent(),
            true
          );
        result = JSONUtilities.readJSON(stringResult);
        addResponseStatus(includeStatusCode, result, response);
      } catch (Throwable ex) {
        exception = ex;
        throw ex;
      } finally {
        if (response != null) {
          if (exception != null) {
            try {
              response.close();
            } catch (Throwable ex) {
              exception.addSuppressed(ex);
            }
          } else {
            response.close();
          }
        }
      }
    }
    return result;
  }

  private void infoTableToMultipart(
    InfoTable infoTable,
    MultipartEntityBuilder builder
  ) {
    for (ValueCollection rowToSend : infoTable.getRows()) {
      for (String fieldName : infoTable.getDataShape().getFields().getNames()) {
        builder.addTextBody(
          fieldName,
          rowToSend.getStringValue(fieldName),
          ContentType.MULTIPART_FORM_DATA
        );
      }
    }
  }

  public CloseableHttpClient createHttpClient(
    String username,
    String password,
    Boolean ignoreSSLErrors,
    Double timeout,
    Boolean useNTLM,
    String workstation,
    String domain,
    Boolean useProxy,
    String proxyHost,
    Integer proxyPort,
    String proxyScheme,
    InputStream certStream,
    String certPass
  ) {
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
      RequestConfig.Builder requestConfigBuilder = RequestConfig
        .custom()
        .setConnectTimeout(httpTimeout)
        .setSocketTimeout(httpTimeout);
      if (useProxy == null) {
        useProxy = false;
      }

      if (
        useProxy && StringUtilities.isNonEmpty(proxyHost) && proxyPort != null
      ) {
        HttpHost proxy = new HttpHost(proxyHost, proxyPort, proxyScheme);
        requestConfigBuilder.setProxy(proxy);
      }

      RequestConfig requestConfig = requestConfigBuilder.build();
      clientBuilder.setDefaultRequestConfig(requestConfig);
      if (ignoreSSLErrors) {
        SSLContextBuilder sslContextBuilder = SSLContexts
          .custom()
          .loadTrustMaterial(null, new TrustSelfSignedStrategy());
        if (certStream != null) {
          // Client keystore
          KeyStore cks = KeyStore.getInstance("PKCS12");
          cks.load(certStream, certPass.toCharArray());
          sslContextBuilder.loadKeyMaterial(cks, certPass.toCharArray());
        }
        SSLContext sslContext = sslContextBuilder.build();
        SSLConnectionSocketFactory sslConnectionFactory = new SSLConnectionSocketFactory(
          sslContext,
          NoopHostnameVerifier.INSTANCE
        );
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

          credsProvider.setCredentials(
            AuthScope.ANY,
            new NTCredentials(username, password, workstation, domain)
          );
        } else {
          credsProvider.setCredentials(
            AuthScope.ANY,
            new UsernamePasswordCredentials(username, password)
          );
        }

        clientBuilder.setDefaultCredentialsProvider(credsProvider);
      }

      return clientBuilder.build();
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  private void addResponseStatus(
    Boolean includeRespStatus,
    JSONObject json,
    CloseableHttpResponse response
  )
    throws JSONException {
    if (includeRespStatus != null && includeRespStatus) {
      JSONObject status = new JSONObject();
      StatusLine statusLine = response.getStatusLine();
      status.put("protocolVersion", statusLine.getProtocolVersion());
      status.put("statusCode", statusLine.getStatusCode());
      status.put("reasonPhrase", statusLine.getReasonPhrase());
      json.put("responseStatus", status);
    }
  }

  public String cookiesToString(List<Cookie> cookies) {
    StringBuilder cookieResult = new StringBuilder();
    if (cookies != null && cookies.size() > 0) {
      boolean isFirst = true;
      Iterator var3 = cookies.iterator();

      while (var3.hasNext()) {
        Cookie cookie = (Cookie) var3.next();
        if (isFirst) {
          isFirst = false;
        } else {
          cookieResult.append("; ");
        }

        cookieResult.append(cookie.getName());
        cookieResult.append('=');
        cookieResult.append(cookie.getValue());
      }
    }

    return cookieResult.toString();
  }
}

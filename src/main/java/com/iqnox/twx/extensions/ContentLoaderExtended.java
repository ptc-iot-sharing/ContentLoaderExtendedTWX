package com.iqnox.twx.extensions;

import com.thingworx.common.RESTAPIConstants;
import com.thingworx.common.RESTAPIConstants.StatusCode;
import com.thingworx.common.exceptions.InvalidRequestException;
import com.thingworx.common.utils.HttpUtilities;
import com.thingworx.common.utils.JSONUtilities;
import com.thingworx.common.utils.StringUtilities;
import com.thingworx.entities.utils.ThingUtilities;
import com.thingworx.logging.LogUtilities;
import com.thingworx.metadata.annotations.ThingworxServiceDefinition;
import com.thingworx.metadata.annotations.ThingworxServiceParameter;
import com.thingworx.metadata.annotations.ThingworxServiceResult;
import com.thingworx.resources.Resource;
import com.thingworx.things.repository.FileRepositoryThing;
import com.thingworx.types.InfoTable;
import com.thingworx.types.collections.ValueCollection;
import java.io.FileInputStream;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import org.apache.commons.io.FilenameUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.json.JSONObject;
import org.json.JSONArray;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class ContentLoaderExtended extends Resource {

  private static final Logger _logger = LogUtilities.getInstance().getApplicationLogger(ContentLoaderExtended.class);

  @ThingworxServiceDefinition(name = "ExecuteHttpRequest", description = "Execute a request for content from a using the specified method", category = "Request")
  @ThingworxServiceResult(name = "result", description = "Loaded content as JSON Object. Actual response is in the response key", baseType = "JSON")
  public JSONObject ExecuteHttpRequest(
    @ThingworxServiceParameter(name = "url", description = "URL to load", baseType = "STRING") String url,
    @ThingworxServiceParameter(name = "method", description = "HTTP method to use", baseType = "STRING") String method,
    @ThingworxServiceParameter(name = "content", description = "Payload that should be sent to the endpoint. Only some methods support setting a payload", baseType = "STRING") String content,
    @ThingworxServiceParameter(name = "contentType", description = "ContentType of the payload to use. Must be specified if content is specified", baseType = "STRING") String contentType,
    @ThingworxServiceParameter(name = "username", description = "Optional user name credential", baseType = "STRING") String username,
    @ThingworxServiceParameter(name = "password", description = "Optional password credential", baseType = "STRING") String password,
    @ThingworxServiceParameter(name = "headers", description = "Optional HTTP headers", baseType = "JSON") JSONObject headers,
    @ThingworxServiceParameter(name = "ignoreSSLErrors", description = "Ignore SSL Certificate Errors", baseType = "BOOLEAN") Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(name = "withCookies", description = "Include cookies in response", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withCookies,
    @ThingworxServiceParameter(name = "withResponseStatus", description = "Include response status", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withResponseStatus,
    @ThingworxServiceParameter(name = "withResponseHeaders", description = "Include response headers", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withResponseHeaders,
    @ThingworxServiceParameter(name = "timeout", description = "Optional timeout in seconds", baseType = "NUMBER", aspects = { "defaultValue:60" }) Double timeout,
    @ThingworxServiceParameter(name = "useNTLM", description = "Use NTLM Authentication", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean useNTLM,
    @ThingworxServiceParameter(name = "workstation", description = "Auth workstation", baseType = "STRING", aspects = { "defaultValue:" }) String workstation,
    @ThingworxServiceParameter(name = "domain", description = "Auth domain", baseType = "STRING", aspects = { "defaultValue:" }) String domain,
    @ThingworxServiceParameter(name = "useProxy", description = "Use Proxy server", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean useProxy,
    @ThingworxServiceParameter(name = "proxyHost", description = "Proxy host", baseType = "STRING", aspects = { "defaultValue:" }) String proxyHost,
    @ThingworxServiceParameter(name = "proxyPort", description = "Proxy port", baseType = "INTEGER", aspects = { "defaultValue:8080" }) Integer proxyPort,
    @ThingworxServiceParameter(name = "proxyScheme", description = "Proxy scheme", baseType = "STRING", aspects = { "defaultValue:http" }) String proxyScheme,
    @ThingworxServiceParameter(name = "keyStorePath", baseType = "STRING", description = "Absolute path to the client SSL keystore") String keyStorePath,
    @ThingworxServiceParameter(name = "keyStorePassword", description = "SSL Keystore Password", baseType = "STRING") String keyStorePassword,
    @ThingworxServiceParameter(name = "trustStorePath", description = "Absolute path to the SSL client truststore", baseType = "STRING") String trustStorePath,
    @ThingworxServiceParameter(name = "trustStorePassword", description = "SSL Truststore Password", baseType = "STRING") String trustStorePassword
  ) throws Exception {
    if (StringUtilities.isNotBlank(content) && StringUtilities.isBlank(contentType)) {
      contentType = "text/plain";
    }

    return executeRequest(
      url,
      method,
      StringUtilities.isNotBlank(content) ? new StringEntity(content, ContentType.create(contentType, StandardCharsets.UTF_8)) : null,
      username,
      password,
      headers,
      ignoreSSLErrors,
      withCookies,
      withResponseStatus,
      withResponseHeaders,
      timeout,
      useNTLM,
      workstation,
      domain,
      useProxy,
      proxyHost,
      proxyPort,
      proxyScheme,
      keyStorePath,
      keyStorePassword,
      trustStorePath,
      trustStorePassword
    );
  }

  @ThingworxServiceDefinition(name = "ExecuteHttpRequests", description = "Wrapper for 'ExecuteHttpRequest' to execute multiple HTTP requests simultaneously", category = "Request")
  @ThingworxServiceResult(name = "result", description = "Array of response objects in 'array' property", baseType = "JSON")
  public JSONObject ExecuteHttpRequests(
    @ThingworxServiceParameter(name = "array", description = "Array of request/parameter objects", baseType = "JSON") JSONObject requestsObj
  ) throws Exception {
    // Prepare JSON output
    JSONArray requests = requestsObj.getJSONArray("array");
    JSONObject out = JSONUtilities.createJSON();
    JSONArray responses = JSONUtilities.createJSONArray();
    out.put("array", responses);

    // Create a callable request list
    List> taskList = new ArrayList<>();
    for (int i = 0; i < requests.length(); i++) {
      JSONObject request = requests.getJSONObject(i);
      taskList.add(() -> {
        try {
          return ExecuteHttpRequest(
            request.optString("url"),
            request.optString("method"),
            request.optString("content"),
            request.optString("username"),
            request.optString("password"),
            request.optString("url"),
            request.optJSONObject("headers"),
            request.optBoolean("ignoreSSLErrors"),
            request.optBoolean("withCookies"),
            request.optBoolean("withResponseStatus"),
            request.optBoolean("withResponseHeaders"),
            request.optDouble("timeout"),
            request.optBoolean("useNTLM"),
            request.optString("workstation"),
            request.optString("domain"),
            request.optBoolean("useProxy"),
            request.optString("proxyHost"),
            request.optInt("proxyPort"),
            request.optString("proxyScheme"),
            request.optString("keyStorePath"),
            request.optString("keyStorePassword"),
            request.optString("trustStorePath"),
            request.optString("trustStorePassword")
          );
        } catch (Exception e) {
          return JSONUtilities.createJSON().put("error", String.valueOf(e));
        }
      });
    }

    // Execute all requests
    ExecutorService executor = Executors.newCachedThreadPool();
    List> futureResponses = executor.invokeAll(taskList);

    // Add response objects to JSON output
    for (Future futureResponse : futureResponses) {
      responses.put(futureResponse.get());
    }

    return out;
  }

  @ThingworxServiceDefinition(name = "ExecuteHttpMultipartRequest", description = "Multipart data upload from Thingworx to and external target via HTTP POST with multiple files", category = "Request")
  @ThingworxServiceResult(name = "result", description = "Response as JSON Object", baseType = "JSON")
  public JSONObject ExecuteHttpMultipartRequest(
    @ThingworxServiceParameter(name = "url", description = "URL to load", baseType = "STRING") String url,
    @ThingworxServiceParameter(name = "partsToSend", description = "Infotable where each row is a multipart part to send", baseType = "INFOTABLE") InfoTable partsToSend,
    @ThingworxServiceParameter(
      name = "filesToSend",
      description = "Infotable where each row is a file that should be sent as part of the multipart request",
      baseType = "INFOTABLE"
    ) InfoTable filesToSend,
    @ThingworxServiceParameter(name = "method", description = "HTTP method to use", baseType = "STRING") String method,
    @ThingworxServiceParameter(name = "username", description = "Optional user name credential", baseType = "STRING") String username,
    @ThingworxServiceParameter(name = "password", description = "Optional password credential", baseType = "STRING") String password,
    @ThingworxServiceParameter(name = "headers", description = "Optional HTTP headers", baseType = "JSON") JSONObject headers,
    @ThingworxServiceParameter(name = "ignoreSSLErrors", description = "Ignore SSL Certificate Errors", baseType = "BOOLEAN") Boolean ignoreSSLErrors,
    @ThingworxServiceParameter(name = "withCookies", description = "Include cookies in response", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withCookies,
    @ThingworxServiceParameter(name = "withResponseStatus", description = "Include response status", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withResponseStatus,
    @ThingworxServiceParameter(name = "withResponseHeaders", description = "Include response headers", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean withResponseHeaders,
    @ThingworxServiceParameter(name = "timeout", description = "Optional timeout in seconds", baseType = "NUMBER", aspects = { "defaultValue:60" }) Double timeout,
    @ThingworxServiceParameter(name = "useNTLM", description = "Use NTLM Authentication", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean useNTLM,
    @ThingworxServiceParameter(name = "workstation", description = "Auth workstation", baseType = "STRING", aspects = { "defaultValue:" }) String workstation,
    @ThingworxServiceParameter(name = "domain", description = "Auth domain", baseType = "STRING", aspects = { "defaultValue:" }) String domain,
    @ThingworxServiceParameter(name = "useProxy", description = "Use Proxy server", baseType = "BOOLEAN", aspects = { "defaultValue:false" }) Boolean useProxy,
    @ThingworxServiceParameter(name = "proxyHost", description = "Proxy host", baseType = "STRING", aspects = { "defaultValue:" }) String proxyHost,
    @ThingworxServiceParameter(name = "proxyPort", description = "Proxy port", baseType = "INTEGER", aspects = { "defaultValue:8080" }) Integer proxyPort,
    @ThingworxServiceParameter(name = "proxyScheme", description = "Proxy scheme", baseType = "STRING", aspects = { "defaultValue:http" }) String proxyScheme,
    @ThingworxServiceParameter(name = "keyStorePath", baseType = "STRING", description = "Absolute path to the client SSL keystore") String keyStorePath,
    @ThingworxServiceParameter(name = "keyStorePassword", description = "SSL Keystore Password", baseType = "STRING") String keyStorePassword,
    @ThingworxServiceParameter(name = "trustStorePath", description = "Absolute path to the SSL client truststore", baseType = "STRING") String trustStorePath,
    @ThingworxServiceParameter(name = "trustStorePassword", description = "SSL Truststore Password", baseType = "STRING") String trustStorePassword
  ) throws Exception {
    if (StringUtilities.isNullOrEmpty(url)) {
      throw new InvalidRequestException("URL parameter cannot be blank", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
    }

    if (partsToSend == null && filesToSend == null) {
      throw new InvalidRequestException("Must have either filesToSend or partsToSend", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
    }

    MultipartEntityBuilder entityBuilder = MultipartEntityBuilder.create();
    if (partsToSend != null) {
      this.infoTableToMultipart(partsToSend, entityBuilder);
    }

    for (ValueCollection row : filesToSend.getRows()) {
      String repository = row.getStringValue("repository");
      String pathOnRepository = row.getStringValue("pathOnRepository");
      String multipartFileName = row.getStringValue("multipartFileName");

      if (!StringUtilities.isNullOrEmpty(repository)) {
        String fileName = FilenameUtils.getName(pathOnRepository);
        if (StringUtilities.isNullOrEmpty(fileName)) {
          throw new InvalidRequestException("Filename could not be found in path: [" + pathOnRepository + "]", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
        }

        FileRepositoryThing repoThing = (FileRepositoryThing) ThingUtilities.findThing(repository);
        if (repoThing == null) {
          throw new InvalidRequestException("File Repository [" + repository + "] does not exist", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
        }

        try {
          byte[] fileData = repoThing.LoadBinary(pathOnRepository);
          String mimeType = URLConnection.guessContentTypeFromName(fileName);
          ContentType contentType = mimeType != null ? ContentType.create(mimeType) : ContentType.APPLICATION_OCTET_STREAM;
          entityBuilder.addBinaryBody(multipartFileName, fileData, contentType, fileName);
        } catch (Exception ex) {
          throw new InvalidRequestException("File [" + fileName + "] in repository [" + repository + "] could not be opened for reading", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
        }
      }
    }

    return executeRequest(
      url,
      method,
      entityBuilder.build(),
      username,
      password,
      headers,
      ignoreSSLErrors,
      withCookies,
      withResponseStatus,
      withResponseHeaders,
      timeout,
      useNTLM,
      workstation,
      domain,
      useProxy,
      proxyHost,
      proxyPort,
      proxyScheme,
      keyStorePath,
      keyStorePassword,
      trustStorePath,
      trustStorePassword
    );
  }

  private JSONObject executeRequest(
    String url,
    String method,
    HttpEntity body,
    String username,
    String password,
    JSONObject headers,
    Boolean ignoreSSLErrors,
    Boolean withCookies,
    Boolean withResponseStatus,
    Boolean withResponseHeaders,
    Double timeout,
    Boolean useNTLM,
    String workstation,
    String domain,
    Boolean useProxy,
    String proxyHost,
    Integer proxyPort,
    String proxyScheme,
    String keyStorePath,
    String keyStorePassword,
    String trustStorePath,
    String trustStorePassword
  ) throws Exception {
    if (StringUtilities.isNullOrEmpty(url)) {
      throw new InvalidRequestException("URL parameter cannot be blank", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
    }
    if (StringUtilities.isNullOrEmpty(method)) {
      throw new InvalidRequestException("Method parameter cannot be blank", RESTAPIConstants.StatusCode.STATUS_BAD_REQUEST);
    }
    SSLContext sslContext = HttpUtilities.createSslContext(keyStorePath, keyStorePassword, trustStorePath, trustStorePassword, ignoreSSLErrors);

    try (
      CloseableHttpClient client = HttpUtilities.createHttpClient(
        username,
        StringUtilities.stringToByteArray(password),
        ignoreSSLErrors,
        timeout,
        useNTLM,
        workstation,
        domain,
        useProxy,
        proxyHost,
        proxyPort,
        proxyScheme,
        sslContext
      )
    ) {
      RequestBuilder requestBuilder = RequestBuilder.create(method).setUri(url);

      if (headers != null) {
        logErrorIfHeaderIsMalformed(headers);
        headers.keySet().forEach(s -> requestBuilder.addHeader(s, headers.getString(s)));
      }

      if (body != null) {
        requestBuilder.setEntity(body);
      }

      HttpClientContext context = HttpUtilities.createClientContext();
      HttpUtilities.enablePremptiveAuthentication(context, url);

      try (CloseableHttpResponse response = client.execute(requestBuilder.build(), context)) {
        JSONObject json = JSONUtilities.createJSON();

        if (response.getStatusLine().getStatusCode() != StatusCode.STATUS_NO_CONTENT.httpCode()) {
          json.put("response", StringUtilities.readFromStream(response.getEntity().getContent(), true));
        }

        if (Boolean.TRUE.equals(withCookies)) {
          json.put("cookies", HttpUtilities.cookiesToString(context.getCookieStore().getCookies()));
        }
        if (Boolean.TRUE.equals(withResponseStatus)) {
          addResponseStatus(json, response);
        }
        if (Boolean.TRUE.equals(withResponseHeaders)) {
          addResponseHeaders(json, response);
        }

        return json;
      }
    }
  }

  private void infoTableToMultipart(InfoTable infoTable, MultipartEntityBuilder builder) {
    for (ValueCollection rowToSend : infoTable.getRows()) {
      for (String fieldName : infoTable.getDataShape().getFields().getNames()) {
        builder.addTextBody(fieldName, rowToSend.getStringValue(fieldName), ContentType.MULTIPART_FORM_DATA);
      }
    }
  }

  private static void logErrorIfHeaderIsMalformed(JSONObject headers) {
    if (headers != null && headers.length() == 0) {
      _logger.error("Error constructing headers JSONObject");
    }
  }

  private static void addResponseStatus(JSONObject json, CloseableHttpResponse response) {
    JSONObject status = JSONUtilities.createJSON();
    StatusLine statusLine = response.getStatusLine();
    status.put("protocolVersion", statusLine.getProtocolVersion());
    status.put("statusCode", statusLine.getStatusCode());
    status.put("reasonPhrase", statusLine.getReasonPhrase());
    json.put("responseStatus", status);
  }

  private static void addResponseHeaders(JSONObject json, CloseableHttpResponse response) {
    JSONObject responseHeaderObj = JSONUtilities.createJSON();
    Header[] resHeaders = response.getAllHeaders();
    String value;
    if (resHeaders != null) {
      for (Header resHeader : resHeaders) {
        value = resHeader.getValue();
        if (StringUtilities.isNullOrEmpty(value)) {
          responseHeaderObj.put(resHeader.getName(), JSONObject.NULL);
        } else {
          responseHeaderObj.put(resHeader.getName(), value);
        }
      }
    }

    json.put("responseHeaders", responseHeaderObj);
  }
}

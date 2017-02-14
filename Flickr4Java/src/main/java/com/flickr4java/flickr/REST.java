/*
 * Copyright (c) 2005 Aetrion LLC.
 */
package com.flickr4java.flickr;

import com.flickr4java.flickr.auth.Auth;
import com.flickr4java.flickr.util.Base64;
import com.flickr4java.flickr.util.DebugInputStream;
import com.flickr4java.flickr.util.IOUtilities;
import com.flickr4java.flickr.util.UrlUtilities;

import org.apache.log4j.Logger;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.apis.FlickrApi;
import com.github.scribejava.core.model.OAuth1AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Token;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuthService;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Transport implementation using the REST interface.
 * 
 * @author Anthony Eden
 * @version $Id: REST.java,v 1.26 2009/07/01 22:07:08 x-mago Exp $
 */
public class REST extends Transport {

    private static final Logger logger = Logger.getLogger(REST.class);

    public static final String PATH = "/services/rest/";

    private static final String CHARSET_NAME = "UTF-8";

    private boolean proxyAuth = false;

    private String proxyUser = "";

    private String proxyPassword = "";

    private final DocumentBuilder builder;

    private static Object mutex = new Object();

    private Integer connectTimeoutMs;

    private Integer readTimeoutMs;

    private ExecutorService executor = Executors.newFixedThreadPool(1);

    /**
     * Construct a new REST transport instance.
     */
    public REST() {
        setTransportType(REST);
        setHost(API_HOST);
        setPath(PATH);
        setScheme(DEFAULT_SCHEME);
        setResponseClass(RESTResponse.class);
        DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
        try {
            builder = builderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new FlickrRuntimeException(e);
        }
    }

    /**
     * Construct a new REST transport instance using the specified host endpoint.
     * 
     * @param host
     *            The host endpoint
     */
    public REST(String host) {
        this();
        setHost(host);
    }

    /**
     * Construct a new REST transport instance using the specified host and port endpoint.
     * 
     * @param host
     *            The host endpoint
     * @param port
     *            The port
     */
    public REST(String host, int port) {
        this();
        setHost(host);
        setPort(port);
    }

    /**
     * Set a proxy for REST-requests.
     * 
     * @param proxyHost
     * @param proxyPort
     */
    public void setProxy(String proxyHost, int proxyPort) {
        System.setProperty("http.proxySet", "true");
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", "" + proxyPort);
        System.setProperty("https.proxyHost", proxyHost);
        System.setProperty("https.proxyPort", "" + proxyPort);
    }

    /**
     * Set a proxy with authentication for REST-requests.
     * 
     * @param proxyHost
     * @param proxyPort
     * @param username
     * @param password
     */
    public void setProxy(String proxyHost, int proxyPort, String username, String password) {
        setProxy(proxyHost, proxyPort);
        proxyAuth = true;
        proxyUser = username;
        proxyPassword = password;
    }

    /**
     * Invoke an HTTP GET request on a remote host. You must close the InputStream after you are done with.
     * 
     * @param path
     *            The request path
     * @param parameters
     *            The parameters (collection of Parameter objects)
     * @return The Response
     */
    @Override
    public Future<Response> get(String path, Map<String, Object> parameters, String apiKey, String sharedSecret) {

        final OAuthRequest request = new OAuthRequest(Verb.GET, getScheme() + "://" + getHost() + path);
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            request.addQuerystringParameter(entry.getKey(), String.valueOf(entry.getValue()));
        }

        if (proxyAuth) {
            request.addHeader("Proxy-Authorization", "Basic " + getProxyCredentials());
        }

        RequestContext requestContext = RequestContext.getRequestContext();
        Auth auth = requestContext.getAuth();
        if (auth != null) {
            OAuth1AccessToken accessToken = new OAuth1AccessToken(auth.getToken(), auth.getTokenSecret());
            OAuthService service = createOAuthService(parameters, apiKey, sharedSecret);
            service.signRequest(accessToken, request);
        } else {
            // For calls that do not require authorization e.g. flickr.people.findByUsername which could be the
            // first call if the user did not supply the user-id (i.e. nsid).
            if (!parameters.containsKey(Flickr.API_KEY)) {
                request.addQuerystringParameter(Flickr.API_KEY, apiKey);
            }
        }

        if (Flickr.debugRequest) {
            logger.debug("GET: " + request.getCompleteUrl());
        }
        setTimeouts(request);
        final OAuthService service = new ServiceBuilder().apiKey(apiKey).apiSecret(sharedSecret).build(FlickrApi.instance());
        service.signRequest(new OAuth1AccessToken(auth.getToken(), auth.getTokenSecret()), request);

        Callable<Response> getRequest = new Callable<Response>() {
            @Override
            public Response call() throws Exception {
                com.github.scribejava.core.model.Response scribeResponse = null;
                try {
                    scribeResponse = service.execute(request);
                } catch (InterruptedException e) {
                    throw new FlickrRuntimeException(e);
                } catch (ExecutionException e) {
                    throw new FlickrRuntimeException(e);
                } catch (IOException e) {
                    throw new FlickrRuntimeException(e);
                }

                try {

                    Response response = null;
                    synchronized (mutex) {
                        String strXml = scribeResponse.getBody().trim();
                        if (Flickr.debugStream) {
                            logger.debug(strXml);
                        }
                        if (strXml.startsWith("oauth_problem=")) {
                            throw new FlickrRuntimeException(strXml);
                        }
                        Document document = builder.parse(new InputSource(new StringReader(strXml)));
                        response = (Response) responseClass.newInstance();
                        response.parse(document);
                    }
                    return response;
                } catch (IllegalAccessException e) {
                    throw new FlickrRuntimeException(e);
                } catch (InstantiationException e) {
                    throw new FlickrRuntimeException(e);
                } catch (SAXException e) {
                    throw new FlickrRuntimeException(e);
                } catch (IOException e) {
                    throw new FlickrRuntimeException(e);
                }
            }
        };

        try {
            return executor.submit(getRequest);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Invoke a non OAuth HTTP GET request on a remote host.
     * 
     * This is only used for the Flickr OAuth methods checkToken and getAccessToken.
     * 
     * @param path
     *            The request path
     * @param parameters
     *            The parameters
     * @return The Response
     */
    @Override
    public Future<Response> getNonOAuth(final String path, final Map<String, String> parameters) {
        Callable<Response> getNonOAuthRequest = new Callable<Response>() {
            @Override
            public Response call() throws Exception {
                InputStream in = null;
                try {
                    URL url = UrlUtilities.buildUrl(getScheme(), getHost(), getPort(), path, parameters);
                    if (Flickr.debugRequest) {
                        logger.debug("GET: " + url);
                    }
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    if (proxyAuth) {
                        conn.setRequestProperty("Proxy-Authorization", "Basic " + getProxyCredentials());
                    }
                    setTimeouts(conn);
                    conn.connect();

                    if (Flickr.debugStream) {
                        in = new DebugInputStream(conn.getInputStream(), System.out);
                    } else {
                        in = conn.getInputStream();
                    }

                    Response response = null;
                    synchronized (mutex) {
                        Document document = builder.parse(in);
                        response = (Response) responseClass.newInstance();
                        response.parse(document);
                    }
                    return response;
                } catch (IllegalAccessException e) {
                    throw new FlickrRuntimeException(e);
                } catch (InstantiationException e) {
                    throw new FlickrRuntimeException(e);
                } catch (IOException e) {
                    throw new FlickrRuntimeException(e);
                } catch (SAXException e) {
                    throw new FlickrRuntimeException(e);
                } finally {
                    IOUtilities.close(in);
                }
            }
        };

        return executor.submit(getNonOAuthRequest);
    }

    /**
     * Invoke an HTTP POST request on a remote host.
     * 
     * @param path
     *            The request path
     * @param parameters
     *            The parameters (collection of Parameter objects)
     * @return The Response object
     */
    @Override
    public Future<Response> post(String path, Map<String, Object> parameters, String apiKey, String sharedSecret, boolean multipart) {

        final OAuthRequest request = new OAuthRequest(Verb.POST, getScheme() + "://" + getHost() + path);

        if (multipart) {
            buildMultipartRequest(parameters, request);
        } else {
            buildNormalPostRequest(parameters, request);
        }

        RequestContext requestContext = RequestContext.getRequestContext();
        Auth auth = requestContext.getAuth();
        if (auth != null) {
            Token accessToken = new OAuth1AccessToken(auth.getToken(), auth.getTokenSecret());
            OAuthService service = createOAuthService(parameters, apiKey, sharedSecret);
            service.signRequest(accessToken, request);
        }

        if (multipart) {
            // Ensure all parameters (including oauth) are added to payload so signature matches
            parameters.putAll(request.getOauthParameters());
            request.setPayload(buildMultipartBody(parameters, getMultipartBoundary()));
        }

        if (proxyAuth) {
            request.addHeader("Proxy-Authorization", "Basic " + getProxyCredentials());
        }

        if (Flickr.debugRequest) {
            logger.debug("POST: " + request.getCompleteUrl());
        }

        setTimeouts(request);
        final OAuthService service = new ServiceBuilder().apiKey(apiKey).apiSecret(sharedSecret).build(FlickrApi.instance());
        service.signRequest(new OAuth1AccessToken(auth.getToken(), auth.getTokenSecret()), request);

        Callable<Response> postRequest = new Callable<Response>() {
            @Override
            public Response call() throws Exception {
                com.github.scribejava.core.model.Response scribeResponse = null;
                try {
                    scribeResponse = service.execute(request);
                } catch (InterruptedException e) {
                    throw new FlickrRuntimeException(e);
                } catch (ExecutionException e) {
                    throw new FlickrRuntimeException(e);
                } catch (IOException e) {
                    throw new FlickrRuntimeException(e);
                }

                try {
                    com.flickr4java.flickr.Response response = null;
                    synchronized (mutex) {
                        String strXml = scribeResponse.getBody().trim();
                        if (Flickr.debugStream) {
                            logger.debug(strXml);
                        }
                        if (strXml.startsWith("oauth_problem=")) {
                            throw new FlickrRuntimeException(strXml);
                        }
                        Document document = builder.parse(new InputSource(new StringReader(strXml)));
                        response = (com.flickr4java.flickr.Response) responseClass.newInstance();
                        response.parse(document);
                    }
                    return response;
                } catch (IllegalAccessException e) {
                    throw new FlickrRuntimeException(e);
                } catch (InstantiationException e) {
                    throw new FlickrRuntimeException(e);
                } catch (SAXException e) {
                    throw new FlickrRuntimeException(e);
                } catch (IOException e) {
                    throw new FlickrRuntimeException(e);
                }
            }
        };

        return executor.submit(postRequest);
    }

    /**
     * 
     * @param parameters
     * @param sharedSecret
     * @return
     */
    private OAuthService createOAuthService(Map<String, Object> parameters, String apiKey, String sharedSecret) {
        ServiceBuilder serviceBuilder = new ServiceBuilder().apiKey(apiKey).apiSecret(sharedSecret);
        if (Flickr.debugRequest) {
            serviceBuilder = serviceBuilder.debug();
        }

        return serviceBuilder.build(FlickrApi.instance());
    }

    /**
     * 
     * @param parameters
     * @param request
     */
    private void buildNormalPostRequest(Map<String, Object> parameters, OAuthRequest request) {
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            request.addBodyParameter(entry.getKey(), String.valueOf(entry.getValue()));
        }
    }

    /**
     * 
     * @param parameters
     * @param request
     */
    private void buildMultipartRequest(Map<String, Object> parameters, OAuthRequest request) {
        request.addHeader("Content-Type", "multipart/form-data; boundary=" + getMultipartBoundary());
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            String key = entry.getKey();
            if (!key.equals("photo") && !key.equals("filename") && !key.equals("filemimetype")) {
                request.addQuerystringParameter(key, String.valueOf(entry.getValue()));
            }
        }
    }

    /**
     * 
     * @return
     */
    private String getMultipartBoundary() {
        return "---------------------------7d273f7a0d3";
    }

    public boolean isProxyAuth() {
        return proxyAuth;
    }

    /**
     * Generates Base64-encoded credentials from locally stored username and password.
     * 
     * @return credentials
     */
    public String getProxyCredentials() {
        return new String(Base64.encode((proxyUser + ":" + proxyPassword).getBytes()));
    }

    private byte[] buildMultipartBody(Map<String, Object> parameters, String boundary) {

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            String filename = (String) parameters.get("filename");
            if (filename == null)
                filename = "image.jpg";

            String fileMimeType = (String) parameters.get("filemimetype");
            if (fileMimeType == null)
                fileMimeType = "image/jpeg";

            buffer.write(("--" + boundary + "\r\n").getBytes(CHARSET_NAME));
            for (Entry<String, Object> entry : parameters.entrySet()) {
                String key = entry.getKey();
                if (!key.equals("filename") && !key.equals("filemimetype"))
                    writeParam(key, entry.getValue(), buffer, boundary, filename, fileMimeType);
            }
        } catch (IOException e) {
            throw new FlickrRuntimeException(e);
        }

        if (Flickr.debugRequest) {
            String output = new String(buffer.toByteArray());
            logger.debug("Multipart body:\n" + output);
        }
        return buffer.toByteArray();
    }

    private void writeParam(String name, Object value, ByteArrayOutputStream buffer, String boundary, String filename, String fileMimeType) throws IOException {
        if (value instanceof InputStream) {
            buffer.write(("Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\";\r\n").getBytes(CHARSET_NAME));
            buffer.write(("Content-Type: " + fileMimeType + "\r\n\r\n").getBytes(CHARSET_NAME));
            InputStream in = (InputStream) value;
            byte[] buf = new byte[512];

            int res = -1;
            while ((res = in.read(buf)) != -1) {
                buffer.write(buf, 0, res);
            }
            buffer.write(("\r\n" + "--" + boundary + "\r\n").getBytes(CHARSET_NAME));
        } else if (value instanceof byte[]) {
            buffer.write(("Content-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\";\r\n").getBytes(CHARSET_NAME));
            buffer.write(("Content-Type: " + fileMimeType + "\r\n\r\n").getBytes(CHARSET_NAME));
            buffer.write((byte[]) value);
            buffer.write(("\r\n" + "--" + boundary + "\r\n").getBytes(CHARSET_NAME));
        } else {
            buffer.write(("Content-Disposition: form-data; name=\"" + name + "\"\r\n\r\n").getBytes(CHARSET_NAME));
            buffer.write(((String) value).getBytes(CHARSET_NAME));
            buffer.write(("\r\n" + "--" + boundary + "\r\n").getBytes(CHARSET_NAME));
        }
    }

    private void setTimeouts(HttpURLConnection conn) {
        if (connectTimeoutMs != null) {
            conn.setConnectTimeout(connectTimeoutMs);
        }
        if (readTimeoutMs != null) {
            conn.setReadTimeout(readTimeoutMs);
        }
    }

    private void setTimeouts(OAuthRequest request) {
        // TODO : Need to handle timeouts when bringing future as scribejava now use modern concurrency
        /* if (connectTimeoutMs != null) {
            request.setConnectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS);
        }
        if (readTimeoutMs != null) {
            request.setReadTimeout(readTimeoutMs, TimeUnit.MILLISECONDS);
        } */
    }

    public void setConnectTimeoutMs(Integer connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public void setReadTimeoutMs(Integer readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }
}

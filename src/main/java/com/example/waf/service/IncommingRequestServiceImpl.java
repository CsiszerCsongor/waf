package com.example.waf.service;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.writer.RequestLogger;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Service
public class IncommingRequestServiceImpl implements IncommingRequestService {
    // TODO beallitani, hogy milyen path-okra milyen domain-t/ip:port-ot hívjon meg

    private String domain;
    private Integer port;
    private String protocol;
    private RequestLogger requestLogger;


    private RequestXssChecker requestXssChecker;

    @Autowired
    public IncommingRequestServiceImpl(
            @Value("${application.request.checker.domain}") String domain,// = "localhost"; // TODO need to change. Should set from properties file
            @Value("${application.request.checker.port}") Integer port,
            @Value("${application.request.checker.protocol}") String protocol,
            RequestLogger requestLogger,
            RequestXssCheckerImpl requestXssChecker){
        this.domain = domain;
        this.port = port;
        this.protocol = protocol;
        this.requestLogger = requestLogger;
        this.requestXssChecker = requestXssChecker;
    }

    @Override
    public ResponseEntity<String> processIncommingRequest(String body,
                                                          HttpMethod httpMethod,
                                                          HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          String traceId ) throws URISyntaxException, IOException {
        log.info("Incomming request: " + request.getQueryString());

        HttpHeaders headers = getHeadersFromRequest(request);

        try{

            checkRequest(request, body);
            return forwardRequest(traceId, headers, body, request, httpMethod);

        } catch (XssThreateningException xssException){
            requestLogger.logXssException(request, headers, xssException);
            // TODO what need to happen, when xss were detected
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                 .headers(headers)
                                 .body("Invalid parameter detected!");
        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getRawStatusCode())
                                 .headers(e.getResponseHeaders())
                                 .body(e.getResponseBodyAsString());
        }
    }

    protected void checkRequest(final HttpServletRequest request, final String body)
            throws XssThreateningException, IOException {
        requestXssChecker.checkRequest(request, body);
    }


    private ResponseEntity<String> forwardRequest(String traceId, HttpHeaders headers, String body, HttpServletRequest request, HttpMethod httpMethod)
            throws URISyntaxException {
        ThreadContext.put("traceId", traceId);

        headers.set("TRACE", traceId);
        headers.remove(HttpHeaders.ACCEPT_ENCODING); // TODO ???

        HttpEntity<String> httpEntity = new HttpEntity<>(body, headers);
        ClientHttpRequestFactory factory = new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory());
        RestTemplate restTemplate = new RestTemplate(factory);

        URI uri = getUriFromRequest(request);

        ResponseEntity<String> serverResponse = restTemplate.exchange(uri, httpMethod, httpEntity, String.class);
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.put(HttpHeaders.CONTENT_TYPE, serverResponse.getHeaders().get(HttpHeaders.CONTENT_TYPE));
        return serverResponse;
    }

    private Map<String, String[]> getQueryParameters(HttpServletRequest request) throws UnsupportedEncodingException {
        Map<String, String[]> queryParameters = new HashMap<>();
        String queryString = request.getQueryString();
        if (StringUtils.hasText(queryString)) {
            queryString = URLDecoder.decode(queryString, StandardCharsets.UTF_8.toString());
            String[] parameters = queryString.split("&");
            for (String parameter : parameters) {
                String[] keyValuePair = parameter.split("=");
                String[] values = queryParameters.get(keyValuePair[0]);

                values = keyValuePair.length == 1 ? ArrayUtils.add(values, "") :
                        ArrayUtils.addAll(values, keyValuePair[1].split(",")); //handles CSV separated query param values.
                queryParameters.put(keyValuePair[0], values);
            }
        }
        return queryParameters;
    }
    protected HttpHeaders getHeadersFromRequest(HttpServletRequest request){
        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.set(headerName, request.getHeader(headerName));
        }

        return headers;
    }

    protected URI getUriFromRequest(HttpServletRequest request) throws URISyntaxException {
        URI uri = new URI(protocol, null, domain, port, null, null, null);
        String requestUrl = request.getRequestURI();

        // replacing context path form urI to match actual gateway URI
        uri = UriComponentsBuilder.fromUri(uri)
                                  .path(requestUrl)
                                  .query(request.getQueryString())
                                  .build(true).toUri();

        return uri;
    }
}

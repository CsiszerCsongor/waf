package com.example.waf.service;

import com.example.waf.exceptions.XssThreateningException;
import com.example.waf.writer.RequestLogger;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;

@Slf4j
public abstract class IncommingRequestServiceBase implements IncommingRequestService {
    private String domain;
    private Integer port;
    private String protocol;
    private RequestLogger requestLogger;

    public IncommingRequestServiceBase(String domain,
                                       Integer port,
                                       String protocol,
                                       RequestLogger requestLogger){
        this.domain = domain;
        this.port = port;
        this.protocol = protocol;
        this.requestLogger = requestLogger;
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
        } catch (XssThreateningException xssException){
            requestLogger.logXssException(request, headers, new XssThreateningException("Error in headers"));
            // TODO what need to happen, when xss were detected
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                 .headers(headers)
                                 .body("Invalid parameter detected!");
        }

        ThreadContext.put("traceId", traceId);

        headers.set("TRACE", traceId);
        headers.remove(HttpHeaders.ACCEPT_ENCODING); // TODO ???

        try {
            HttpEntity<String> httpEntity = new HttpEntity<>(body, headers);
            ClientHttpRequestFactory factory = new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory());
            RestTemplate restTemplate = new RestTemplate(factory);

            URI uri = getUriFromRequest(request);

            ResponseEntity<String> serverResponse = restTemplate.exchange(uri, httpMethod, httpEntity, String.class);
            HttpHeaders responseHeaders = new HttpHeaders();
            responseHeaders.put(HttpHeaders.CONTENT_TYPE, serverResponse.getHeaders().get(HttpHeaders.CONTENT_TYPE));
            return serverResponse;

        } catch (HttpStatusCodeException e) {
            return ResponseEntity.status(e.getRawStatusCode())
                                 .headers(e.getResponseHeaders())
                                 .body(e.getResponseBodyAsString());
        }
    }

    protected abstract void checkRequest(HttpServletRequest request, String body)
            throws XssThreateningException, IOException;

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

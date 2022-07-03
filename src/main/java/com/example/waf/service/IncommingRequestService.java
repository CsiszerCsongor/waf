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
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Service
public class IncommingRequestService {

    @Value("${application.request.checker.domain}")
    private String domain; // = "localhost"; // TODO need to change. Should set from properties file

    @Value("${application.request.checker.port}")
    private Integer port;

    @Value("${application.request.checker.protocol}")
    private String protocol;

    private RequestLogger requestLogger;
    private XssRegexLoader xssRegexLoader;

    @Autowired
    public IncommingRequestService(RequestLogger requestLogger,
                                   XssRegexLoader xssRegexLoader){
        this.requestLogger = requestLogger;
        this.xssRegexLoader = xssRegexLoader;
    }

    // TODO beallitani, hogy milyen path-okra milyen domai-t/ip:port-ot hívjon meg

    public ResponseEntity<String> processIncommingRequest(String body,
                                                          HttpMethod httpMethod,
                                                          HttpServletRequest request,
                                                          HttpServletResponse response,
                                                          String traceId ) throws URISyntaxException {
        log.info("Incomming request: " + request.getQueryString());
        // request.getCookies
        // request.getHeaderNames -> iterate over header names
        // request.getParameterNames -> iterate over parameter names

        HttpHeaders headers = new HttpHeaders();
        Enumeration<String> headerNames = request.getHeaderNames();

        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            headers.set(headerName, request.getHeader(headerName));
        }

        try{
           checkParametersAgainstXss(request);
// TODO          checkHeadersAgainstXss(request);
// TODO          checkCookiesAgainstXss();
// TODO          checkBodyAgainstXss(request);
        } catch (XssThreateningException xssException){
            requestLogger.logXssException(request, headers, new XssThreateningException("Error in headers"));
        }

        ThreadContext.put("traceId", traceId);
        String requestUrl = request.getRequestURI();

        URI uri = new URI(protocol, null, domain, port, null, null, null);

        // replacing context path form urI to match actual gateway URI
        // TODO request check against XSS
        uri = UriComponentsBuilder.fromUri(uri)
                .path(requestUrl)
                .query(request.getQueryString())
                .build(true).toUri();

        // TODO header check against XSS
        headers.set("TRACE", traceId);
        headers.remove(HttpHeaders.ACCEPT_ENCODING); // TODO ???

        HttpEntity<String> httpEntity = new HttpEntity<>(body, headers);
        ClientHttpRequestFactory factory = new BufferingClientHttpRequestFactory(new SimpleClientHttpRequestFactory());
        RestTemplate restTemplate = new RestTemplate(factory);

        try {

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

    private void checkParametersAgainstXss(HttpServletRequest request) throws XssThreateningException{
        Enumeration<String> parameterNames = request.getParameterNames();

        while (parameterNames.hasMoreElements()) {
            String parameterName = parameterNames.nextElement();
            if (textContainsMaliciousCode(request.getParameter(parameterName))) {
                throw new XssThreateningException("Malicious code detected in parameter : " + parameterName +
                        "\nParameter value : " + request.getParameter(parameterName));
            }
        }
    }

    private boolean textContainsMaliciousCode(String text){
        for (Pattern pattern : xssRegexLoader.getPatterns()) {
            if (pattern.matcher(text).find()){
                return true;
            }
        }

        return false;
    }
}

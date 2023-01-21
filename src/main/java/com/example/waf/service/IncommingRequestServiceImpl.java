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
public class IncommingRequestServiceImpl extends IncommingRequestServiceBase {

    private RequestXssChecker requestXssChecker;

    @Autowired
    public IncommingRequestServiceImpl(
            @Value("${application.request.checker.domain}") String domain, // = "localhost"; // TODO need to change. Should set from properties file
            @Value("${application.request.checker.port}") Integer port,
            @Value("${application.request.checker.protocol}") String protocol,
            RequestLogger requestLogger,
            RequestXssChecker requestXssChecker){
        super(domain, port, protocol, requestLogger);
        this.requestXssChecker = requestXssChecker;
    }

    // TODO beallitani, hogy milyen path-okra milyen domain-t/ip:port-ot hívjon meg

    @Override
    protected void checkRequest(final HttpServletRequest request, final String body)
            throws XssThreateningException, IOException {
        requestXssChecker.checkRequest(request, body);
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

}

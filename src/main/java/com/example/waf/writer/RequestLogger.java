package com.example.waf.writer;

import com.example.waf.exceptions.XssThreateningException;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Component
public class RequestLogger {
    // TODO write into database requests

    public void logXssException(HttpServletRequest request, HttpHeaders headers, XssThreateningException xssThreateningException){
        //TODO save into database error message
        StringBuilder stringBuilder = new StringBuilder();
        Map<String, String> requestInformation = getRequestInformation(request);
        Iterator it = requestInformation.entrySet().iterator();

        stringBuilder.append("XSS threatening exception : " + xssThreateningException.getMessage() + "\n");

        while (it.hasNext()) {
            Map.Entry pair = (Map.Entry)it.next();
            stringBuilder.append(pair.getKey() + " = " + pair.getValue() + "\n");
        }

        log.error(stringBuilder.toString());
    }

    private Map<String, String> getRequestInformation(HttpServletRequest request) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("Method", request.getMethod());
        map.put("Protocol", request.getProtocol());
        map.put("RequestUrl", request.getRequestURL().toString());
        map.put("QueryString", request.getQueryString());

        Enumeration headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String key = (String) headerNames.nextElement();
            String value = request.getHeader(key);
            map.put("header: " + key, value);
        }
        Enumeration parameterNames = request.getParameterNames();
        while (parameterNames.hasMoreElements()) {
            String key = (String) parameterNames.nextElement();
            String value = request.getParameter(key);
            map.put("parameter: " + key, value);
        }
        Cookie[] cookies = request.getCookies();
        for (int i = 0; i < cookies.length; i++) {
            Cookie cookie = cookies[i];
            map.put("cookie: " + cookie.getName(), cookie.getValue());

        }
        while (parameterNames.hasMoreElements()) {
            String key = (String) parameterNames.nextElement();
            String value = request.getParameter(key);
            map.put("parameter: " + key, value);
        }
//        map.put("getRequestIPAdrress", getRequestIPAdrress(request.getI));
        map.put("getRemoteUser", request.getRemoteUser());
        map.put("getAuthType", request.getAuthType());
        map.put("getContextPath", request.getContextPath());
        map.put("getPathInfo", request.getPathInfo());
        map.put("getPathTranslated", request.getPathTranslated());
        map.put("getRequestedSessionId", request.getRequestedSessionId());
        map.put("getRequestURI", request.getRequestURI());
        map.put("getServletPath", request.getServletPath());
        map.put("getContentType", request.getContentType());
        map.put("getLocalName", request.getLocalName());
        map.put("getRemoteAddr", request.getRemoteAddr());
        map.put("getServerName", request.getServerName());
        return map;
    }
}


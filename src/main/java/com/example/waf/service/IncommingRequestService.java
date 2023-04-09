package com.example.waf.service;

import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;

public interface IncommingRequestService {
    ResponseEntity<String> processIncommingRequest(String body,
                                                   HttpMethod httpMethod,
                                                   HttpServletRequest request,
                                                   HttpServletResponse response,
                                                   String traceId ) throws URISyntaxException, IOException;
}

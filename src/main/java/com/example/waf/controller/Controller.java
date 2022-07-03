package com.example.waf.controller;

import com.example.waf.service.IncommingRequestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.util.UUID;

@RestController
public class Controller {

    private IncommingRequestService incommingRequestService;

    @Autowired
    public Controller(IncommingRequestService incommingRequestService){
        this.incommingRequestService = incommingRequestService;
    }

    @GetMapping("/**")
    public ResponseEntity<String> incommingGetRequestsController(
            @RequestBody(required = false) String body,
            HttpMethod method,
            HttpServletRequest request,
            HttpServletResponse response
            ) throws URISyntaxException, UnsupportedEncodingException {

        return incommingRequestService.processIncommingRequest(body,
                method,
                request,
                response,
                UUID.randomUUID().toString());

    }

    @PostMapping("/**")
    public ResponseEntity<String> incommingPostRequestsController(
            @RequestBody(required = false) String body,
            HttpMethod method,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws URISyntaxException, UnsupportedEncodingException {

        return incommingRequestService.processIncommingRequest(body,
                method,
                request,
                response,
                UUID.randomUUID().toString());

    }

}

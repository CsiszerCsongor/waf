package com.example.waf.service;

import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class DecoderService {

    public static String decodeUntilIsNotDecoded(String text) {
        String decodedString = URLDecoder.decode(text, StandardCharsets.UTF_8);

        while (!decodedString.equals(text)){
            text = decodedString;
            decodedString = URLDecoder.decode(text, StandardCharsets.UTF_8);
        }

        while (text.contains("&") || text.contains("#") || text.contains(";")){
            text = StringEscapeUtils.unescapeHtml4(text);
        }

        text = text.toLowerCase();

        return text;
    }

}

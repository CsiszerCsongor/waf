package com.example.waf.service;

import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.Scanner;
import java.util.regex.Pattern;

@Component
@NoArgsConstructor
public class XssRegexLoader {

    // TODO controller ennek, hogy API-n kerersztul is be lehessen tolteni
    // TODO legyen a fajlban egy sor pelfa, majd alatta a regex

    private String filepath;

    private LinkedList<Pattern> patternList;

    public void XssRegexLoader(@Value("${application.xss.loader.source") String filepath) throws IOException {
        try(Scanner scanner = new Scanner(new File(filepath))){
            while(scanner.hasNext()){
                String line = scanner.nextLine();
                // TODO connect regex with comment(contains example for regex)
                if (!line.startsWith("#")){
                    patternList.add(Pattern.compile(line));
                }
            }
        }
    }

    public LinkedList<Pattern> getPatterns(){
        return patternList;
    }
}

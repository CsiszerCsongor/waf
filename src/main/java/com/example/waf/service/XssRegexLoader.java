package com.example.waf.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

@Slf4j
@Component
public class XssRegexLoader {

    // TODO controller ennek, hogy API-n kerersztul is be lehessen tolteni
    // TODO legyen a fajlban egy sor pelda, majd alatta a regex

    private String CLASSPATH = "classpath:";

    private final LinkedList<String> regexAgainstAnyHtmlTagString;
    private final LinkedList<String> blacklistedHtmlTagsStringList;
    private final LinkedList<String> blacklistedHtmlTagAttributesStringList;
    private final LinkedList<String> whitelistedHtmlTagsStringList;
    private final LinkedList<String> whitelistedHtmlTagAttributesStringList;

    private LinkedList<Pattern> regexAgainstAnyHtmlTag;
    private LinkedList<Pattern> blacklistedHtmlTagsList;
    private LinkedList<Pattern> blacklistedHtmlTagAttributesList;
    private LinkedList<Pattern> whitelistedHtmlTagsList;
    private LinkedList<Pattern> whitelistedHtmlTagAttributesList;

    public XssRegexLoader(@Value("${application.regex.against.xss.payloads.loader.source}") String regexAgainstXssSourcePath,
                          @Value("${application.default.blacklisted.html.tags.source}") String blacklistedHtmlTagListSourcePath,
                          @Value("${application.default.blacklisted.html.events.source}") String blacklistedHtmlTagAttributesListSourcePath,
                          @Value("${application.default.whitelisted.html.tags.source}") String regexWhitelistedHtmlTags,
                          @Value("${application.default.whitelisted.html.events.source}") String regexWhitelistedHtmlTagAttributes
                          ) {
        regexAgainstAnyHtmlTagString = new LinkedList<>();
        blacklistedHtmlTagsStringList = new LinkedList<>();
        blacklistedHtmlTagAttributesStringList = new LinkedList<>();
        whitelistedHtmlTagsStringList = new LinkedList<>();
        whitelistedHtmlTagAttributesStringList = new LinkedList<>();

        readRegexFile(CLASSPATH + regexAgainstXssSourcePath, regexAgainstAnyHtmlTagString);
        readRegexFile(CLASSPATH + blacklistedHtmlTagListSourcePath, blacklistedHtmlTagsStringList);
        readRegexFile(CLASSPATH + blacklistedHtmlTagAttributesListSourcePath, blacklistedHtmlTagAttributesStringList);
        readRegexFile(CLASSPATH + regexWhitelistedHtmlTags, whitelistedHtmlTagsStringList);
        readRegexFile(CLASSPATH + regexWhitelistedHtmlTagAttributes, whitelistedHtmlTagAttributesStringList);

        deleteFromBlacklistWhitelistedHtmlTagsAndAttributes();
        convertStringListsToRegexPatterns();
    }

    private void convertStringListsToRegexPatterns(){
        regexAgainstAnyHtmlTag = new LinkedList<>();
        blacklistedHtmlTagsList = new LinkedList<>();
        blacklistedHtmlTagAttributesList = new LinkedList<>();
        whitelistedHtmlTagsList = new LinkedList<>();
        whitelistedHtmlTagAttributesList = new LinkedList<>();

        for (String blacklistedHtmlTag : blacklistedHtmlTagsStringList) {
            blacklistedHtmlTagsList.add(Pattern.compile(blacklistedHtmlTag));
        }

        for (String blacklistedHtmlTagAttribute : blacklistedHtmlTagAttributesStringList) {
            blacklistedHtmlTagAttributesList.add(Pattern.compile(blacklistedHtmlTagAttribute));
        }

        for (String whitelistedHtmlTag : whitelistedHtmlTagsStringList) {
            whitelistedHtmlTagsList.add(Pattern.compile(whitelistedHtmlTag));
        }

        for (String whitelistedHtmlTagAttribute : whitelistedHtmlTagAttributesStringList) {
            whitelistedHtmlTagAttributesList.add(Pattern.compile(whitelistedHtmlTagAttribute));
        }

        for (String anyHtmlTag : regexAgainstAnyHtmlTagString) {
            regexAgainstAnyHtmlTag.add(Pattern.compile(anyHtmlTag));
        }
    }

    public List<Pattern> getRegexAgainstAnyHtmlTagPatterns(){
        return regexAgainstAnyHtmlTag;
    }
    public List<Pattern> getBlacklistedHtmlTagsList(){
        return blacklistedHtmlTagsList;
    }
    public List<Pattern> getBlacklistedHtmlTagAttributesList(){
        return blacklistedHtmlTagAttributesList;
    }
    public List<Pattern> getWhitelistedHtmlTagsList(){
        return whitelistedHtmlTagsList;
    }
    public List<Pattern> getWhitelistedHtmlTagAttributesList(){
        return whitelistedHtmlTagAttributesList;
    }

    private void readRegexFile(String path, LinkedList<String> regexPatternList){
        try(Scanner scanner = new Scanner(ResourceUtils.getFile(path))) {
            while(scanner.hasNext()){
                String line = scanner.nextLine();
                // TODO connect regex with comment(contains example for regex)
                regexPatternList.add(line);
            }
        } catch (FileNotFoundException e) {
            log.error("File not found  :  " + path);
        }
    }

    private void deleteFromBlacklistWhitelistedHtmlTagsAndAttributes(){
        for (String whitelistedHtmlTagAttributeString : whitelistedHtmlTagAttributesStringList ){
            blacklistedHtmlTagAttributesStringList.remove(whitelistedHtmlTagAttributeString);
        }

        for (String whitelistedHtmlTagString : whitelistedHtmlTagsStringList){
            blacklistedHtmlTagsStringList.remove(whitelistedHtmlTagString);
        }
    }
}

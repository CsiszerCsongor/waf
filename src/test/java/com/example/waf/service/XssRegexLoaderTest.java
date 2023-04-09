package com.example.waf.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class XssRegexLoaderTest {
    private XssRegexLoader xssRegexLoader;

    private final String regexAgainstXssSourcePath = "patterns/blacklist/xssPayloadRegex.txt";
    private final String regexBlacklistedHtmlTagListSourcePath = "patterns/blacklist/html_tags.txt";
    private final String regexBlacklistedHtmlTagAttributesListSourcePath = "patterns/blacklist/html_tag_attributes.txt";
    private final String regexWhitelistedHtmlTagListSourcePath = "patterns/whitelist/html_tags.txt";
    private final String regexWhitelistedHtmlTagAttributesListSourcePath = "patterns/whitelist/html_tag_attributes.txt";

    private final LinkedList<String> regexAgainstXssStringList = new LinkedList<>();
    private final LinkedList<String> regexBlacklistedHtmlTagStringList = new LinkedList<>();
    private final LinkedList<String> regexBlacklistedHtmlTagAttributesStringList = new LinkedList<>();
    private final LinkedList<String> regexWhitelistedHtmlTagStringList = new LinkedList<>();
    private final LinkedList<String> regexWhitelistedHtmlTagAttributesStringList = new LinkedList<>();

    @BeforeEach
    void init(){
        xssRegexLoader = new XssRegexLoader(
                regexAgainstXssSourcePath,
                regexBlacklistedHtmlTagListSourcePath,
                regexBlacklistedHtmlTagAttributesListSourcePath,
                regexWhitelistedHtmlTagListSourcePath,
                regexWhitelistedHtmlTagAttributesListSourcePath);

        readRegexFile(regexAgainstXssSourcePath, regexAgainstXssStringList);
        readRegexFile(regexBlacklistedHtmlTagListSourcePath, regexBlacklistedHtmlTagStringList);
        readRegexFile(regexBlacklistedHtmlTagAttributesListSourcePath, regexBlacklistedHtmlTagAttributesStringList);
        readRegexFile(regexWhitelistedHtmlTagListSourcePath, regexWhitelistedHtmlTagStringList);
        readRegexFile(regexWhitelistedHtmlTagAttributesListSourcePath, regexWhitelistedHtmlTagAttributesStringList);
    }

    @Test
    @DisplayName("Should read files on paths and create patterns from regexes in those")
    void shouldReadFilesOnPathsAndCreatePatternsFromRegexesInThose() {
        assertAll(
                () -> assertTrue(checkPatternListAgainstHtmlTagOrAttributeStringFromFile(xssRegexLoader.getRegexAgainstAnyHtmlTagPatterns(), regexAgainstXssStringList), "Regex against any xss string list does not match"),
                () -> assertTrue(checkPatternListAgainstHtmlTagOrAttributeStringFromFile(xssRegexLoader.getWhitelistedHtmlTagsList(), regexWhitelistedHtmlTagStringList), "Whitelist reges pattern list does not match"),
                () -> assertTrue(checkPatternListAgainstHtmlTagOrAttributeStringFromFile(xssRegexLoader.getWhitelistedHtmlTagAttributesList(), regexWhitelistedHtmlTagAttributesStringList)),
                () -> assertEquals(regexBlacklistedHtmlTagStringList.size() - regexWhitelistedHtmlTagStringList.size(), xssRegexLoader.getBlacklistedHtmlTagsList().size(), "Size of blacklisted html tags is not as expected"),
                () -> assertEquals(regexBlacklistedHtmlTagAttributesStringList.size() - regexWhitelistedHtmlTagAttributesStringList.size(), xssRegexLoader.getBlacklistedHtmlTagAttributesList().size(), "Size of blacklisted html attributes is not as expected"),
                () -> assertTrue(checkIfBlacklistContainsEveryRegexWhichWasNotWhitelisted(xssRegexLoader.getBlacklistedHtmlTagsList(), regexWhitelistedHtmlTagStringList, regexBlacklistedHtmlTagStringList), "Blacklisted html tags are not as expected"),
                () -> assertTrue(checkIfBlacklistContainsEveryRegexWhichWasNotWhitelisted(xssRegexLoader.getBlacklistedHtmlTagAttributesList(), regexWhitelistedHtmlTagAttributesStringList, regexBlacklistedHtmlTagAttributesStringList), "Blacklisted html tag attributes are not as expected")
                );
    }

    private boolean checkPatternListAgainstHtmlTagOrAttributeStringFromFile(List<Pattern> patternList, LinkedList<String> regexStringList) {
        for (String regexFromFile : regexStringList){
            if (regexNotExistsInPatternList(regexFromFile, patternList)){
                System.out.println("Regex: " + regexFromFile);
                return false;
            }
        }

        return true;
    }

    private boolean checkIfBlacklistContainsEveryRegexWhichWasNotWhitelisted(List<Pattern> blacklistPattern, List<String> whitelistStringList, List<String> blacklistStringList) {
        List<String> expectedBacklistedRegexList = deleteFromBlacklistWhitelistedRegex(blacklistStringList, whitelistStringList);

        for (String regex : expectedBacklistedRegexList){
            if (regexNotExistsInPatternList(regex, blacklistPattern)){
                System.out.println("Regex: " + regex);
                return false;
            }
        }

        return true;
    }

    private boolean regexNotExistsInPatternList(String regexFromFile, List<Pattern> patternList){
        for (Pattern pattern : patternList) {
            if (pattern.pattern().equals(regexFromFile)){
                return false;
            }
        }

        return true;
    }

    private void readRegexFile(String path, LinkedList<String> regexPatternList){
        path = "classpath:" + path;
        try(Scanner scanner = new Scanner(ResourceUtils.getFile(path))) {
            while(scanner.hasNext()){
                String line = scanner.nextLine();
                // TODO connect regex with comment(contains example for regex)
                regexPatternList.add(line);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    private List<String> deleteFromBlacklistWhitelistedRegex(List<String> blacklist, List<String> whitelist){
        for (String whitelistedHtmlTagString : whitelist){
            blacklist.remove(whitelistedHtmlTagString);
        }

        return blacklist;
    }
}
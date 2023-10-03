package com.analyzer.sbom.service;

import com.analyzer.sbom.dto.response.SbomResponseDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SbomService {

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper;

    @Value("${webclient.nvd}")
    private String cveUrl;

    @Value("${webclient.nvdSelector}")
    private String nvdSelector;

    @Value("${webclient.snyk}")
    private String snykUrl;

    @Value("${webclient.snykXpath}")
    private String snykXpath;

    @Value("${webclient.snykSearchXpath}")
    private String snykSearchXpath;

    @Value("${webclient.snykBase}")
    private String snykBase;

    public JsonNode scanVulnerability(String token, String projectId, String baseUrl) throws JsonProcessingException {
        String jsonData = getAPI(token, projectId, baseUrl);
        return objectMapper.readTree(jsonData);
    }

    public List<SbomResponseDto> generateReport(String token, String projectId, String baseUrl) throws IOException {
        String sbomResult = getAPI(token, projectId, baseUrl);

        List<SbomResponseDto> sbomReport = new ArrayList<>();

        JsonNode jsonNode = objectMapper.readTree(sbomResult).get("findings");
        if (jsonNode.isArray()) {
            for (JsonNode finding : jsonNode) {
                JsonNode component = finding.get("component");
                String name =  isExist(component, "name") ? component.get("name").asText() : "";
                String version = isExist(component, "version") ? component.get("version").asText() : "";
                String purl = isExist(component, "purl") ? component.get("purl").asText() : "";
                String group = isExist(component, "group") ? component.get("group").asText() : "";

                JsonNode attribution = finding.get("attribution");
                String suggestionLink = isExist(attribution, "referenceUrl") ? attribution.get("referenceUrl").asText() : "";

                JsonNode vulnerability = finding.get("vulnerability");
                String severity = isExist(vulnerability, "severity") ? vulnerability.get("severity").asText() : "";
                String vulnId = isExist(vulnerability, "vulnId") ? vulnerability.get("vulnId").asText() : "";
                String source = isExist(vulnerability, "source") ? vulnerability.get("source").asText() : "";
                String description = isExist(vulnerability, "description") ? vulnerability.get("description").asText() : "";

                String referenceUrl = cveUrl + vulnId;

                List<String> suggestionUrl = getSuggestionUrl(referenceUrl);
                suggestionUrl.add(getSuggestion(snykUrl + vulnId, true));
                if(!Objects.equals(suggestionLink, "")) suggestionUrl.add(suggestionLink);

                String suggestion = getSuggestion(snykUrl + vulnId, false);

                SbomResponseDto sbomResponseDto = SbomResponseDto.builder()
                        .name(name)
                        .version(version)
                        .purl(purl)
                        .group(group)
                        .severity(severity)
                        .vulnId(vulnId)
                        .source(source)
                        .description(description)
                        .referenceUrl(referenceUrl)
                        .suggestionUrl(suggestionUrl)
                        .suggestion(suggestion)
                        .build();

                sbomReport.add(sbomResponseDto);
            }
        }
        return sbomReport;
    }

    private String getAPI(String token, String projectId, String baseUrl) {
        WebClient webClient = webClientBuilder
                .baseUrl(baseUrl)
                .defaultHeader("X-Api-Key", token)
                .build();

        return webClient
                .get()
                .uri("/api/v1/finding/project/{projectId}/export", projectId)
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    private boolean isExist(JsonNode source, String fieldName) {
        return source.has(fieldName);
    }

    private List<String> getSuggestionUrl(String cveUrl) throws IOException {
        Document doc = Jsoup.connect(cveUrl).get();
        Element table = doc.select(nvdSelector).first();
        Elements tdElements = Objects.requireNonNull(table).select("td");

        return tdElements.stream()
                .flatMap(td -> td.select("a").stream())
                .map(Element::text)
                .collect(Collectors.toList());
    }

    private String getSuggestion(String snykUrl, Boolean isLink) throws IOException {
        Document doc = Jsoup.connect(snykUrl).get();
        String link = String.join("", doc.selectXpath(snykXpath).eachAttr("href"));
        String suggestionLink = snykBase + link;

        Document solutionDoc = Jsoup.connect(suggestionLink).get();
        String suggestion = solutionDoc.selectXpath(snykSearchXpath).text();

        return isLink ? suggestionLink : suggestion;
    }

}

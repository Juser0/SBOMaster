package com.analyzer.sbom.service;

import com.analyzer.sbom.domain.Reference;
import com.analyzer.sbom.domain.Suggestion;
import com.analyzer.sbom.dto.request.ReferenceRequestDto;
import com.analyzer.sbom.dto.request.SuggestionRequestDto;
import com.analyzer.sbom.dto.response.SbomResponseDto;
import com.analyzer.sbom.repository.ReferenceRepository;
import com.analyzer.sbom.repository.SuggestionRepository;
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
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SbomService {

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper;
    private final SuggestionRepository suggestionRepository;
    private final ReferenceRepository referenceRepository;

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
            for (JsonNode finding : jsonNode) {
                JsonNode component = finding.get("component");
                String name =  parseText(component, "name");
                String version = parseText(component, "text");
                String purl = parseText(component, "purl");
                String group = parseText(component, "group");

                JsonNode attribution = finding.get("attribution");
                String suggestionLink = parseText(attribution, "referenceUrl");

                JsonNode vulnerability = finding.get("vulnerability");
                String severity = parseText(vulnerability, "severity");
                String vulnId = parseText(vulnerability, "vulnId");
                String source = parseText(vulnerability, "source");
                String description = parseText(vulnerability, "description");

                String referenceUrl = cveUrl + vulnId;

                List<String> suggestionUrl = getSuggestionUrl(vulnId, referenceUrl);
                suggestionUrl.add(getSuggestion(vulnId, snykUrl + vulnId, true));
                if(!Objects.equals(suggestionLink, "")) suggestionUrl.add(suggestionLink);

                String suggestion = getSuggestion(vulnId, snykUrl + vulnId, false);

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

    private List<String> getSuggestionUrl(String vulnId, String cveUrl) throws IOException {
        if(!referenceRepository.existsByCveId(vulnId)) {
            Document doc = Jsoup.connect(cveUrl).get();
            Element table = doc.select(nvdSelector).first();
            Elements tdElements = Objects.requireNonNull(table).select("td");

            List<String> referenceList = tdElements.stream()
                    .flatMap(td -> td.select("a").stream())
                    .map(Element::text)
                    .collect(Collectors.toList());

            for (String url : referenceList) {
                ReferenceRequestDto requestDto = new ReferenceRequestDto(vulnId, url);
                referenceRepository.save(requestDto.toEntity());
            }
        }
        return referenceRepository.findAllByCveId(vulnId).stream()
                .map(Reference::getReferenceUrl)
                .collect(Collectors.toList());
    }

    private String getSuggestion(String vulnId, String snykUrl, Boolean isLink) throws IOException {
        if(!suggestionRepository.existsByCveId(vulnId)) {
            Document doc = Jsoup.connect(snykUrl).get();
            String link = String.join("", doc.selectXpath(snykXpath).eachAttr("href"));
            String suggestionLink = snykBase + link;

            if (isLink) return suggestionLink;

            Document solutionDoc = Jsoup.connect(suggestionLink).get();
            String suggestion = solutionDoc.selectXpath(snykSearchXpath).text();

            SuggestionRequestDto requestDto = new SuggestionRequestDto(vulnId, suggestion, suggestionLink);
            suggestionRepository.save(requestDto.toEntity());
        }
        Suggestion suggestion = suggestionRepository.findByCveId(vulnId)
                .orElseThrow(() -> new RuntimeException("Data Not Found"));
        return isLink ? suggestion.getSuggestionUrl() : suggestion.getSuggestion();
    }

    private String parseText(JsonNode source, String subject) {
        return source.has(subject) ? source.get(subject).asText() : "";
    }
}

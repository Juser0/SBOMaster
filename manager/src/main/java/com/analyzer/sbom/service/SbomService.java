package com.analyzer.sbom.service;

import com.analyzer.sbom.dto.response.SbomResponseDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SbomService {

    private final WebClient.Builder webClientBuilder;
    private final ObjectMapper objectMapper;

    @Value("${webclient.nvd}")
    private String ref;

    public JsonNode scanVulnerability(String token, String projectId, String baseUrl) throws JsonProcessingException {
        String jsonData = getAPI(token, projectId, baseUrl);
        return objectMapper.readTree(jsonData);
    }

    public List<SbomResponseDto> generateReport(String token, String projectId, String baseUrl) throws JsonProcessingException {
        String sbomResult = getAPI(token, projectId, baseUrl);

        List<SbomResponseDto> sbomReport = new ArrayList<SbomResponseDto>();

        JsonNode jsonNode = objectMapper.readTree(sbomResult).get("findings");
        if (jsonNode.isArray()) {
            for (JsonNode finding : jsonNode) {
                JsonNode component = finding.get("component");
                String name =  isExist(component, "name") ? component.get("name").asText() : "";
                String version = isExist(component, "version") ? component.get("version").asText() : "";
                String purl = isExist(component, "purl") ? component.get("purl").asText() : "";
                String group = isExist(component, "group") ? component.get("group").asText() : "";

                JsonNode attribution = finding.get("attribution");
                String recommendUrl = isExist(attribution, "referenceUrl") ? attribution.get("referenceUrl").asText() : "";

                JsonNode vulnerability = finding.get("vulnerability");
                String severity = isExist(vulnerability, "severity") ? vulnerability.get("severity").asText() : "";
                String vulnId = isExist(vulnerability, "vulnId") ? vulnerability.get("vulnId").asText() : "";
                String source = isExist(vulnerability, "source") ? vulnerability.get("source").asText() : "";
                String description = isExist(vulnerability, "description") ? vulnerability.get("description").asText() : "";

                String referenceUrl = ref + vulnId;

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
                        .recommendUrl(null)
                        .suggestion("")
                        .build();

                sbomReport.add(sbomResponseDto);
            }
        }
        return sbomReport;
    }

    public String getAPI(String token, String projectId, String baseUrl) {
        WebClient webClient = webClientBuilder
                .baseUrl(baseUrl)
                .defaultHeader("X-Api-Key", token)
                .build();

        String sbomResult = webClient
                .get()
                .uri("/api/v1/finding/project/{projectId}/export", projectId)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        return sbomResult;
    }

    private boolean isExist(JsonNode source, String fieldName) {
        return source.has(fieldName);
    }

    private String getSuggestionUrl() {
        return "";
    }

    private String getSuggestion() {
        return "";
    }

}

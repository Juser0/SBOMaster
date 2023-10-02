package com.analyzer.sbom.dto.response;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class SbomResponseDto {
    private String name;
    private String purl;
    private String version;
    private String group;
    private String vulnId;
    private String severity;
    private String description;
    private String source;
    private String referenceUrl;
    private String suggestion;
    private List<String> recommendUrl;

    @Builder
    public SbomResponseDto(String name, String purl, String version, String group, String vulnId, String severity, String description, String source, String referenceUrl, String suggestion, List<String> recommendUrl) {
        this.name = name;
        this.purl = purl;
        this.version = version;
        this.group = group;
        this.vulnId = vulnId;
        this.severity = severity;
        this.description = description;
        this.source = source;
        this.referenceUrl = referenceUrl;
        this.suggestion = suggestion;
        this.recommendUrl = recommendUrl;
    }
}

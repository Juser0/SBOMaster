package com.analyzer.sbom.dto.request;

import com.analyzer.sbom.domain.Suggestion;
import lombok.Getter;

import javax.validation.constraints.NotBlank;

@Getter
public class SuggestionRequestDto {

    @NotBlank
    private String cveId;

    @NotBlank
    private String suggestion;

    @NotBlank
    private String suggestionUrl;

    public SuggestionRequestDto(String cveId, String suggestion, String suggestionUrl) {
        this.cveId = cveId;
        this.suggestion = suggestion;
        this.suggestionUrl = suggestionUrl;
    }

    public Suggestion toEntity() {
        return new Suggestion(this);
    }
}

package com.analyzer.sbom.dto.response;

import com.analyzer.sbom.domain.Suggestion;
import lombok.Getter;

import javax.validation.constraints.NotBlank;

@Getter
public class SuggestionResponseDto {

    @NotBlank
    private Long id;

    @NotBlank
    private String cveId;

    @NotBlank
    private String suggestion;

    @NotBlank
    private String suggestionUrl;

    private SuggestionResponseDto(Suggestion suggestion) {
        this.id = suggestion.getId();
        this.cveId = suggestion.getCveId();
        this.suggestion =  suggestion.getSuggestion();
        this.suggestionUrl = suggestion.getSuggestionUrl();
    }

    public static SuggestionResponseDto from(Suggestion suggestion) {
        return new SuggestionResponseDto(suggestion);
    }
}

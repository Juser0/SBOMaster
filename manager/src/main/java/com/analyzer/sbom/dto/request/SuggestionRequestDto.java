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

    public Suggestion toEntity(SuggestionRequestDto requestDto) {
        return new Suggestion(requestDto);
    }
}

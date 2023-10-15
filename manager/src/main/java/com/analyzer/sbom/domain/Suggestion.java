package com.analyzer.sbom.domain;

import com.analyzer.sbom.dto.request.SuggestionRequestDto;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Getter
@Table(name = "suggestion_tb")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Suggestion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve")
    private String cveId;

    private String suggestion;

    @Column(name = "suggestion_url")
    private String suggestionUrl;

    public Suggestion(SuggestionRequestDto requestDto) {
        this.cveId = requestDto.getCveId();
        this.suggestion = requestDto.getSuggestion();
        this.suggestionUrl = requestDto.getSuggestionUrl();
    }
}

package com.analyzer.sbom.repository;

import com.analyzer.sbom.domain.Suggestion;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SuggestionRepository extends JpaRepository<Suggestion, Long> {
    Optional<Suggestion> findByCveId(String cveId);
    boolean existsByCveId(String cveId);
}

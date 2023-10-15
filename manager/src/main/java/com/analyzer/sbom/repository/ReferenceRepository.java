package com.analyzer.sbom.repository;

import com.analyzer.sbom.domain.Reference;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ReferenceRepository extends JpaRepository<Reference, Long> {
    Optional<Reference> findByCveId(String cveId);
    boolean existsByCveId(String cveId);

    List<Reference> findAllByCveId(String cveId);
}

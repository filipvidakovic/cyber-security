package org.cybersecurity.controllers.pki;

import lombok.RequiredArgsConstructor;
import org.cybersecurity.config.security.CrlConfig;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/crls")
@RequiredArgsConstructor
public class CrlController {

    private final CrlConfig crlConfig;

    @GetMapping("/{filename}.crl")
    public ResponseEntity<Resource> getCrl(@PathVariable String filename) throws IOException {
        Path folder = Paths.get(crlConfig.getCrlFolder());
        if (!Files.exists(folder)) {
            Files.createDirectories(folder);
            System.out.println("Created CRL folder at: " + folder.toAbsolutePath());
        }

        Path file = folder.resolve(filename + ".crl");

        if (!Files.exists(file)) {
            Files.createFile(file);
            System.out.println("Created empty CRL file: " + file.toAbsolutePath());
        }

        Resource resource = new UrlResource(file.toUri());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/pkix-crl")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + filename + ".crl")
                .body(resource);
    }
}

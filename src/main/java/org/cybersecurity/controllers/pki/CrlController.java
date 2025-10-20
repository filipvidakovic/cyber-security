package org.cybersecurity.controllers.pki;

import lombok.RequiredArgsConstructor;

import org.cybersecurity.services.pki.CrlService;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/crls")
@RequiredArgsConstructor
public class CrlController {

    private final CrlService crlService;
    @GetMapping("/{ca_id}")
    public ResponseEntity<?> downloadCrl(@PathVariable("ca_id") String caIdParam) {
        System.out.println(">>> CRL endpoint hit for issuer: " + caIdParam);

        try {
            Long issuerId = Long.parseLong(caIdParam.substring(3));
            byte[] crlBytes = crlService.generateCrl(issuerId);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"crl-ca-" + issuerId + ".crl\"")
                    .contentType(MediaType.valueOf("application/pkix-crl"))
                    .body(crlBytes);

        } catch (NumberFormatException e) {
            System.err.println("Invalid CA ID format: " + caIdParam);
            return ResponseEntity.badRequest()
                    .body(("Invalid CA ID: " + caIdParam + ". Expected numeric ID (e.g. '10').").getBytes());
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.internalServerError()
                    .body(("Failed to generate CRL for " + caIdParam + ": " + ex.getMessage()).getBytes());
        }
    }

}

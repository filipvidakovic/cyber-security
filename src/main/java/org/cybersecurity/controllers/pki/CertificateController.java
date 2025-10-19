package org.cybersecurity.controllers.pki;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.cybersecurity.dto.pki.*;
import org.cybersecurity.services.pki.CaService;
import org.cybersecurity.services.pki.DownloadService;
import org.cybersecurity.services.pki.EEIssueService;
import org.cybersecurity.services.pki.CertificateService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/api/cert")
@RequiredArgsConstructor
public class CertificateController {

    private final CaService ca;
    private final EEIssueService ee;
    private final DownloadService dl;
    private final CertificateService cs;


    @PostMapping("/root")
    @PreAuthorize("hasAnyRole('ADMIN')")
    public Long createRoot(@RequestBody @Valid CreateRootReq req) throws Exception {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ca.createRoot(req.getCn(), Duration.ofDays(req.getTtlDays()),email,req.getExtensions());
    }

    @PostMapping("/intermediate")
    @PreAuthorize("hasAnyRole('ADMIN','CA_USER')")
    public Long createInt(@RequestBody @Valid CreateIntReq req) throws Exception {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ca.createIntermediate(req.getIssuerId(), req.getCn(), Duration.ofDays(req.getTtlDays()),email,req.getExtensions());
    }

    @PostMapping("/ee/autogen")
    @PreAuthorize("hasAnyRole('ADMIN','CA_USER','USER')")
    public Long issueEeAutogen(@RequestBody @Valid IssueEeAutogenReq req) throws Exception {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ee.issueAutogen(
                req.getIssuerId(),
                req.getCn(),
                Duration.ofDays(req.getTtlDays()),
                req.isStorePrivateKey(),
                email, req.getExtensions()
        );
    }

    @PostMapping(value = "/ee/from-csr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','CA_USER','USER')")
    public Long issueEeFromCsr(@RequestParam Long issuerId,
                               @RequestParam int ttlDays,
                               @RequestPart("csr") MultipartFile csr) throws Exception {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return ee.issueFromCsr(issuerId, csr.getBytes(), Duration.ofDays(ttlDays),email);
    }

    @GetMapping("/{id}/download.p12")
    @PreAuthorize("hasAnyRole('ADMIN','CA_USER','USER')")
    public ResponseEntity<byte[]> p12(@PathVariable Long id,
                                      @RequestHeader("X-P12-Password") String pwd) throws Exception {
        // If no key -> serve PEM instead of error
        if (!dl.hasPrivateKey(id)) {
            byte[] pem = dl.downloadPem(id);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cert-" + id + ".pem\"")
                    .contentType(MediaType.valueOf("application/x-pem-file"))
                    .body(pem);
        }

        // Otherwise return the PKCS#12 as before
        byte[] data = dl.downloadP12(id, pwd.toCharArray());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cert-" + id + ".p12\"")
                .contentType(MediaType.valueOf("application/x-pkcs12"))
                .body(data);
    }


    @PostMapping("/revoke")
    public ResponseEntity<String> revoke(@RequestParam Long certId, @RequestParam int reasonCode) throws Exception {
        cs.revokeCertificate(certId, reasonCode);
        return ResponseEntity.ok("Certificate revoked successfully");
    }


    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<CertificateDTO>> getAllCertificates() {
        return ResponseEntity.ok(cs.getAllCertificates());
    }

    @GetMapping("/ca")
    @PreAuthorize("hasRole('CA_USER')")
    public ResponseEntity<List<CertificateDTO>> getCaUserCertificates() {
        return ResponseEntity.ok(cs.getCaUserCertificates());
    }

    @GetMapping("/user")
    @PreAuthorize("hasAnyRole('USER','CA_USER','ADMIN')")
    public ResponseEntity<List<CertificateDTO>> getUserCertificates() {
        return ResponseEntity.ok(cs.getUserCertificates());
    }

    @GetMapping("/issuers")
    public ResponseEntity<List<IssuerDTO>> getIssuers() {
        return ResponseEntity.ok(cs.getPossibleIssuers());
    }





}

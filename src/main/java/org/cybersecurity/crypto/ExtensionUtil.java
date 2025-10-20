package org.cybersecurity.crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;

import java.util.*;
import java.util.function.BiConsumer;

public final class ExtensionUtil {

    private ExtensionUtil() {}

    /** Handlers keyed by OID (string), value is the raw string from client. */
    private static final Map<String, BiConsumer<Ctx, String>> HANDLERS = Map.of(
            // KeyUsage (critical)
            "2.5.29.15", (ctx, val) -> {
                int usage = 0;
                String s = val.toLowerCase(Locale.ROOT);
                if (s.contains("digitalsignature")) usage |= KeyUsage.digitalSignature;
                if (s.contains("nonrepudiation"))   usage |= KeyUsage.nonRepudiation;
                if (s.contains("keyencipherment"))  usage |= KeyUsage.keyEncipherment;
                if (s.contains("dataencipherment")) usage |= KeyUsage.dataEncipherment;
                if (s.contains("keyagreement"))     usage |= KeyUsage.keyAgreement;
                if (s.contains("keycertsign"))      usage |= KeyUsage.keyCertSign;
                if (s.contains("crlsign"))          usage |= KeyUsage.cRLSign;
                if (s.contains("encipheronly"))     usage |= KeyUsage.encipherOnly;
                if (s.contains("decipheronly"))     usage |= KeyUsage.decipherOnly;
                add(ctx, "2.5.29.15", true, new KeyUsage(usage));
            },

            // Extended Key Usage (non-critical)
            "2.5.29.37", (ctx, val) -> {
                String[] parts = Arrays.stream(val.split(",")).map(String::trim).toArray(String[]::new);
                List<KeyPurposeId> ids = new ArrayList<>();
                for (String p : parts) {
                    switch (p) {
                        case "serverAuth"      -> ids.add(KeyPurposeId.id_kp_serverAuth);
                        case "clientAuth"      -> ids.add(KeyPurposeId.id_kp_clientAuth);
                        case "codeSigning"     -> ids.add(KeyPurposeId.id_kp_codeSigning);
                        case "emailProtection" -> ids.add(KeyPurposeId.id_kp_emailProtection);
                        case "timeStamping"    -> ids.add(KeyPurposeId.id_kp_timeStamping);
                        case "OCSPSigning"     -> ids.add(KeyPurposeId.id_kp_OCSPSigning);
                        default -> {}
                    }
                }
                if (!ids.isEmpty()) add(ctx, "2.5.29.37", false, new ExtendedKeyUsage(ids.toArray(KeyPurposeId[]::new)));
            },

            // Subject Alternative Name (non-critical)
            "2.5.29.17", (ctx, val) -> {
                // supports: DNS:example.com, IP:1.2.3.4, EMAIL:a@b.com, URI:https://...
                String[] items = Arrays.stream(val.split(",")).map(String::trim).toArray(String[]::new);
                List<GeneralName> gns = new ArrayList<>();
                for (String it : items) {
                    int i = it.indexOf(':');
                    if (i <= 0) throw new IllegalArgumentException("SAN entry must be Type:Value");
                    String type = it.substring(0, i).trim().toUpperCase(Locale.ROOT);
                    String v = it.substring(i + 1).trim();
                    switch (type) {
                        case "DNS"   -> gns.add(new GeneralName(GeneralName.dNSName, v));
                        case "IP"    -> gns.add(new GeneralName(GeneralName.iPAddress, v));
                        case "EMAIL" -> gns.add(new GeneralName(GeneralName.rfc822Name, v));
                        case "URI"   -> gns.add(new GeneralName(GeneralName.uniformResourceIdentifier, v));
                        default -> throw new IllegalArgumentException("Unsupported SAN type: " + type);
                    }
                }
                add(ctx, "2.5.29.17", false, new GeneralNames(gns.toArray(GeneralName[]::new)));
            }
    );

    /** Context for handlers. */
    public static class Ctx {
        public final X509v3CertificateBuilder b;
        public Ctx(X509v3CertificateBuilder b){this.b = b;}
    }

    private static void add(Ctx ctx, String oid, boolean critical, ASN1Encodable extVal) {
        try {
            ctx.b.addExtension(new ASN1ObjectIdentifier(oid), critical, extVal);
        } catch (CertIOException e) {
            throw new RuntimeException("Failed to add extension " + oid, e);
        }
    }

    /**
     * Apply user-selected extensions.
     * @param map oid -> value string (as accepted by handlers)
     * @param isCa whether cert is CA (we’ll still enforce CA/EE safety elsewhere)
     */
    public static void apply(X509v3CertificateBuilder b, Map<String, String> map, boolean isCa) {
        if (map == null || map.isEmpty()) return;
        Ctx ctx = new Ctx(b);

        // Defensive: reject illegal CA/EE combinations here if needed.
        // Example: EE cannot request keyCertSign/cRLSign
        if (!isCa) {
            String ku = map.get("2.5.29.15");
            if (ku != null) {
                String s = ku.toLowerCase(Locale.ROOT);
                if (s.contains("keycertsign") || s.contains("crlsign")) {
                    throw new IllegalArgumentException("EE KeyUsage cannot include keyCertSign or cRLSign");
                }
            }
        }

        for (var e : map.entrySet()) {
            var h = HANDLERS.get(e.getKey());
            if (h != null) h.accept(ctx, e.getValue());
            // Unknown OIDs ignored (or throw — your choice)
        }
    }
}

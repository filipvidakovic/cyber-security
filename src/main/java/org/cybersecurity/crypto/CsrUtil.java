package org.cybersecurity.crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.util.*;

public final class CsrUtil {
    private CsrUtil(){}

    /** Returns a map: OID -> value string, understood by ExtensionUtil handlers. */
    public static Map<String,String> extractExtensions(PKCS10CertificationRequest csr){
        Map<String,String> out = new HashMap<>();
        Attribute[] atts = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (atts == null || atts.length == 0) return out;

        ASN1Encodable attrValue = atts[0].getAttrValues().getObjectAt(0);
        Extensions exts = Extensions.getInstance(attrValue);

        for (ASN1ObjectIdentifier oid : exts.getExtensionOIDs()) {
            Extension ext = exts.getExtension(oid);
            String id = oid.getId();
            try {
                switch (id) {
                    case "2.5.29.15" -> { // KeyUsage
                        KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
                        List<String> usages = new ArrayList<>();
                        byte b0 = ku.getBytes()[0];
                        if ((b0 & KeyUsage.digitalSignature) != 0) usages.add("digitalSignature");
                        if ((b0 & KeyUsage.nonRepudiation)   != 0) usages.add("nonRepudiation");
                        if ((b0 & KeyUsage.keyEncipherment)  != 0) usages.add("keyEncipherment");
                        if ((b0 & KeyUsage.dataEncipherment) != 0) usages.add("dataEncipherment");
                        if ((b0 & KeyUsage.keyAgreement)     != 0) usages.add("keyAgreement");
                        if ((b0 & KeyUsage.keyCertSign)      != 0) usages.add("keyCertSign");
                        if ((b0 & KeyUsage.cRLSign)          != 0) usages.add("cRLSign");
                        if ((b0 & KeyUsage.encipherOnly)     != 0) usages.add("encipherOnly");
                        if ((b0 & KeyUsage.decipherOnly)     != 0) usages.add("decipherOnly");
                        out.put(id, String.join(",", usages));
                    }
                    case "2.5.29.37" -> { // EKU
                        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(ext.getParsedValue());
                        List<String> ps = new ArrayList<>();
                        for (KeyPurposeId kp : eku.getUsages()) {
                            if (kp.equals(KeyPurposeId.id_kp_serverAuth))       ps.add("serverAuth");
                            else if (kp.equals(KeyPurposeId.id_kp_clientAuth))  ps.add("clientAuth");
                            else if (kp.equals(KeyPurposeId.id_kp_codeSigning)) ps.add("codeSigning");
                            else if (kp.equals(KeyPurposeId.id_kp_emailProtection)) ps.add("emailProtection");
                            else if (kp.equals(KeyPurposeId.id_kp_timeStamping))    ps.add("timeStamping");
                            else if (kp.equals(KeyPurposeId.id_kp_OCSPSigning))     ps.add("OCSPSigning");
                        }
                        if (!ps.isEmpty()) out.put(id, String.join(",", ps));
                    }
                    case "2.5.29.17" -> { // SAN
                        GeneralNames gns = GeneralNames.getInstance(ext.getParsedValue());
                        List<String> vals = new ArrayList<>();
                        for (GeneralName gn : gns.getNames()) {
                            switch (gn.getTagNo()) {
                                case GeneralName.dNSName -> vals.add("DNS:" + gn.getName());
                                case GeneralName.iPAddress -> vals.add("IP:" + gn.getName());
                                case GeneralName.rfc822Name -> vals.add("EMAIL:" + gn.getName());
                                case GeneralName.uniformResourceIdentifier -> vals.add("URI:" + gn.getName());
                                default -> {}
                            }
                        }
                        if (!vals.isEmpty()) out.put(id, String.join(",", vals));
                    }
                    default -> {}
                }
            } catch (Exception ignore) {}
        }
        return out;
    }
}

package io.mosip.certify.model;

import java.util.Map;

public class MobileSecurityObject {
    private String version;
    private String digestAlgorithm;
    private Map<String, byte[]> valueDigests;
    private String docType;

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    public String getDigestAlgorithm() { return digestAlgorithm; }
    public void setDigestAlgorithm(String digestAlgorithm) { this.digestAlgorithm = digestAlgorithm; }
    public Map<String, byte[]> getValueDigests() { return valueDigests; }
    public void setValueDigests(Map<String, byte[]> valueDigests) { this.valueDigests = valueDigests; }
    public String getDocType() { return docType; }
    public void setDocType(String docType) { this.docType = docType; }
} 
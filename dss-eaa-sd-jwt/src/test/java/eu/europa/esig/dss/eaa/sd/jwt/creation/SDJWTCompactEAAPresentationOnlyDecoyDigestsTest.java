package eu.europa.esig.dss.eaa.sd.jwt.creation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;

class SDJWTCompactEAAPresentationOnlyDecoyDigestsTest extends AbstractSDJWTEAAPresentationTestIssuance {

    private SDJWTEAAPayloadParameters payloadParameters;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new SDJWTEAAPayloadParameters();
        payloadParameters.setIssuer("EAA provider");

        payloadParameters.setVerifiableCredentialsType("urn:eudi:eaa:1");
        Digest digest = new Digest(DigestAlgorithm.SHA256, DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()));
        payloadParameters.setVerifiableCredentialsTypeIntegrity(digest);

        payloadParameters.nonSelectivelyDisclosable().setGivenName("John");
        payloadParameters.nonSelectivelyDisclosable().setFamilyName("Doe");
        payloadParameters.nonSelectivelyDisclosable().setIssuingAuthority("TEST Authority");

        payloadParameters.setDecoyDigestNumber(2);

        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected SDJWTEAAPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected SDJWTKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        EAAWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        assertEquals("urn:eudi:eaa:1", eaa.getEAAVerifiableCredentialsTypeUri());
        assertEquals(DigestAlgorithm.SHA256, eaa.getEAAVerifiableCredentialsTypeIntegrityDigestAlgorithm());
        assertArrayEquals(DSSUtils.digest(DigestAlgorithm.SHA256, "vct".getBytes()), eaa.getEAAVerifiableCredentialsTypeIntegrityBytes());
        assertEquals(DSSUtils.formatDateToRFC(getSignatureParameters().bLevel().getSigningDate()), DSSUtils.formatDateToRFC(eaa.getEAANotBefore()));
        assertEquals(DSSUtils.formatDateToRFC(getSigningCert().getNotAfter()), DSSUtils.formatDateToRFC(eaa.getEAAExpiration()));
        assertEquals("EAA provider", eaa.getEAAIssuer());
        assertEquals("TEST Authority", eaa.getDocumentIssuingAuthority());
        assertEquals("John", eaa.getHolderGivenName());
        assertEquals("Doe", eaa.getHolderFamilyName());

        assertEquals(2, eaa.getDigestMatchers().size());

        int sdCounter = 0;
        int orphanCounter = 0;
        for (XmlDigestMatcher xmlDigestMatcher : eaa.getDigestMatchers()) {
            if (DigestMatcherType.EAA_DISCLOSURE == xmlDigestMatcher.getType()) {
                ++sdCounter;
            } else if (DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == xmlDigestMatcher.getType()) {
                ++orphanCounter;
            }
        }
        assertEquals(0, sdCounter);
        assertEquals(2, orphanCounter);
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected boolean disclosuresPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}

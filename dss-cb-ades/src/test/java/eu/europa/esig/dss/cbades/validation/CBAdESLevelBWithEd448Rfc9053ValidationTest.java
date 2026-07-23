package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.validationreport.jaxb.SignatureIdentifierType;
import eu.europa.esig.xmldsig.jaxb.DigestMethodType;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CBAdESLevelBWithEd448Rfc9053ValidationTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-level-b-ed448-rfc9053.cose");
    }

    @Override
    protected void checkSignatureValue(DiagnosticData diagnosticData) {
        super.checkSignatureValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.ED448, signature.getSignatureAlgorithm()); // alg: -8
    }

    @Override
    protected void validateETSISignatureIdentifier(SignatureIdentifierType signatureIdentifier) {
        assertNotNull(signatureIdentifier);
        assertNotNull(signatureIdentifier.getId());
        assertNotNull(signatureIdentifier.getDigestAlgAndValue());
        DigestMethodType digestMethod = signatureIdentifier.getDigestAlgAndValue().getDigestMethod();
        assertNotNull(digestMethod);
        assertNotNull(digestMethod.getAlgorithm());
        assertEquals(DigestAlgorithm.SHAKE256_512, DigestAlgorithm.forOID(DSSUtils.getOidCode(digestMethod.getAlgorithm())));
        assertNotNull(signatureIdentifier.getDigestAlgAndValue().getDigestValue());
        assertNotNull(signatureIdentifier.getSignatureValue());
    }

}

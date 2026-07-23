package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CBAdESLevelBWithEcdsaWithP256Rfc9053ValidationTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-level-b-ecdsa-P-256-rfc9053.cose");
    }

    @Override
    protected void checkSignatureValue(DiagnosticData diagnosticData) {
        super.checkSignatureValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.ECDSA_SHA256, signature.getSignatureAlgorithm()); // alg: -7
        assertEquals("256" , signature.getKeyLengthUsedToSignThisToken());
    }

}

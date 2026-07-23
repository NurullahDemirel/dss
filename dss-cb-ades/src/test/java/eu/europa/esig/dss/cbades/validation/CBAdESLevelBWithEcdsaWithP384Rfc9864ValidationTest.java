package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CBAdESLevelBWithEcdsaWithP384Rfc9864ValidationTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-level-b-ecdsa-P-384-rfc9864.cose");
    }

    @Override
    protected void checkSignatureValue(DiagnosticData diagnosticData) {
        super.checkSignatureValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(SignatureAlgorithm.ECDSA_SHA384, signature.getSignatureAlgorithm()); // alg: -51
        assertEquals("384" , signature.getKeyLengthUsedToSignThisToken());
    }

}

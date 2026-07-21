package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

class SDJWTJsonSerializationEAAMultipleSignaturesTest extends AbstractSDJWTEAAPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-json-multiple-signatures.json"));
    }

    @Override
    protected int expectedSignaturesCount() {
        return 2;
    }

}

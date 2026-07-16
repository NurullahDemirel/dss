package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORNull;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.eaa.common.validation.DefaultEAAPresentationValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.test.validation.AbstractTestDocumentValidator;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocIssuerSignedEAAPresentationValidatorTest extends AbstractTestDocumentValidator {

    private static final DSSDocument MINIMAL_ISSUER_SIGNED = buildMinimalIssuerSigned();

    private static DSSDocument buildMinimalIssuerSigned() {
        CBORMap issuerSigned = new CBORMap();
        issuerSigned.put("issuerAuth", buildCoseSign1());
        return new InMemoryDocument(CBORUtils.serializeCborObject(issuerSigned));
    }

    private static CBORArray buildCoseSign1() {
        CBORArray coseSign1 = new CBORArray(4);
        coseSign1.add(new CBORByteString());
        coseSign1.add(new CBORMap());
        coseSign1.add(new CBORNull());
        coseSign1.add(new CBORByteString());
        coseSign1.toDataItem().setTag(18L);
        return coseSign1;
    }

    @Test
    void test() {
        MdocIssuerSignedEAAPresentationValidator validator = new MdocIssuerSignedEAAPresentationValidator();

        DSSDocument mdoc = MINIMAL_ISSUER_SIGNED;
        assertTrue(validator.isSupported(mdoc));

        CBORMap nameSpacesOnly = new CBORMap();
        nameSpacesOnly.put("nameSpaces", new CBORMap());
        mdoc = new InMemoryDocument(CBORUtils.serializeCborObject(nameSpacesOnly));
        assertTrue(validator.isSupported(mdoc));

        CBORMap bothKeys = new CBORMap();
        bothKeys.put("nameSpaces", new CBORMap());
        bothKeys.put("issuerAuth", buildCoseSign1());
        mdoc = new InMemoryDocument(CBORUtils.serializeCborObject(bothKeys));
        assertTrue(validator.isSupported(mdoc));

        CBORMap wrongKeyMap = new CBORMap();
        wrongKeyMap.put("test", 1);
        DSSDocument wrong = new InMemoryDocument(CBORUtils.serializeCborObject(wrongKeyMap));
        assertFalse(validator.isSupported(wrong));
        wrong = new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(CBORUtils.serializeCborObject(new CBORArray()));
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("hello".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("eyJhbGciOiJIUzI1NiJ9.c2lnaA.c2lnaA~".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument("<xml/>".getBytes());
        assertFalse(validator.isSupported(wrong));
        wrong = new InMemoryDocument(new byte[]{});
        assertFalse(validator.isSupported(wrong));
        wrong = InMemoryDocument.createEmptyDocument();
        assertFalse(validator.isSupported(wrong));
    }

    @Override
    protected SignedDocumentValidator initEmptyValidator() {
        return new MdocIssuerSignedEAAPresentationValidator();
    }

    @Override
    protected SignedDocumentValidator initValidator(DSSDocument document) {
        return new MdocIssuerSignedEAAPresentationValidator(document);
    }

    @Override
    protected List<DSSDocument> getValidDocuments() {
        return Collections.singletonList(MINIMAL_ISSUER_SIGNED);
    }

    @Override
    protected DSSDocument getMalformedDocument() {
        return new InMemoryDocument(CBORUtils.serializeCborObject(new CBORArray()));
    }

    @Override
    protected DSSDocument getOtherTypeDocument() {
        return new FileDocument("src/test/resources/validation/mdocRefImpl.mdoc");
    }

    @Override
    protected DSSDocument getNoSignatureDocument() {
        // not applicable
        return null;
    }

    @Override
    protected DSSDocument getXmlEvidenceRecordDocument() {
        // not applicable
        return null;
    }

    @Override
    @Test
    public void validateFromDocument() {
        List<DSSDocument> documents = getValidDocuments();
        for (DSSDocument document : documents) {
            DocumentValidator reader = DefaultEAAPresentationValidator.fromDocument(document);
            validate(reader, true);
        }
    }

    @Override
    protected void validate(DocumentValidator validator, boolean containsSignature) {
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        assertNotNull(reports);
        SimpleReport simpleReport = reports.getSimpleReport();
        assertNotNull(simpleReport);
        assertEquals(containsSignature, simpleReport.getFirstEAAId() != null);
    }

}

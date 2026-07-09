/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.eaa.common.validation;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlEAA;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EAARevocationTokenWrapper;
import eu.europa.esig.dss.diagnostic.EAARevocationWrapper;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAADocument;
import eu.europa.esig.dss.diagnostic.jaxb.XmlEAAPresentationInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSignature;
import eu.europa.esig.dss.spi.eaa.EAA;
import eu.europa.esig.dss.spi.eaa.EAAPresentation;
import eu.europa.esig.dss.spi.eaa.status.EAARevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.test.validation.AbstractDocumentTestValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.eaa.EAAPresentationValidator;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractEAAPresentationTestValidation extends AbstractDocumentTestValidation {

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        DefaultEAAPresentationValidator validator = DefaultEAAPresentationValidator.fromDocument(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        validator.setTokenExtractionStrategy(getTokenExtractionStrategy());
        validator.setSignaturePolicyProvider(getSignaturePolicyProvider());
        validator.setTokenIdentifierProvider(getTokenIdentifierProvider());
        validator.setSigningCertificateSource(getSigningCertificateSource());
        validator.setEAARevocationSource(getEAAStatusSource());
        return validator;
    }

    protected EAARevocationSource getEAAStatusSource() {
        return null;
    }

    @Override
    protected void checkValidationContext(SignedDocumentValidator validator) {
        super.checkValidationContext(validator);

        EAAPresentationValidator eaaValidator = assertInstanceOf(EAAPresentationValidator.class, validator);
        EAAPresentation eaaPresentation = eaaValidator.getEAAPresentation();
        assertNotNull(eaaPresentation);
        assertNotNull(eaaPresentation.getEAAPresentationType());

        List<EAA> eaas = eaaPresentation.getElectronicAttestationsOfAttributes();
        assertEquals(1, Utils.collectionSize(eaas));

        EAA eaa = eaas.get(0);
        assertNotNull(eaa.getId());
        assertNotNull(eaa.getDSSId());

        assertEquals(expectedSignaturesCount(), eaa.getSignatures().size());
        assertEquals(disclosuresPresent() || orphanSelectivelyDisclosableClaimsPresent(), Utils.isCollectionNotEmpty(eaa.getDisclosureValidations()));
        assertEquals(keyBindingPresent(), eaa.getKeyBindingSignature() != null);
        assertEquals(getEAAType(), eaa.getEAAType());
    }

    @Override
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        // skip
    }

    @Override
    protected void verifyDiagnosticData(DiagnosticData diagnosticData) {
        super.verifyDiagnosticData(diagnosticData);

        checkEAAPresentationInfo(diagnosticData);
        checkEAAs(diagnosticData);
        checkEAAStatusTokens(diagnosticData);
    }

    protected void checkEAAPresentationInfo(DiagnosticData diagnosticData) {
        XmlEAAPresentationInfo eaaPresentationInfo = diagnosticData.getEAAPresentationInfo();
        assertNotNull(eaaPresentationInfo);
        assertNotNull(eaaPresentationInfo.getEAAPresentationType());
        assertEquals(eaaPresentationInfo.getEAAPresentationType(), diagnosticData.getEAAPresentationType());
        List<XmlEAADocument> documents = eaaPresentationInfo.getDocuments();
        assertTrue(Utils.isCollectionNotEmpty(documents));
        assertEquals(documents.size(), diagnosticData.getEAAs().size());
    }

    protected void checkEAAs(DiagnosticData diagnosticData) {
        List<EAAWrapper> eaas = diagnosticData.getEAAs();
        assertEquals(1, eaas.size());

        EAAWrapper eaaWrappper = eaas.get(0);
        assertNotNull(eaaWrappper.getId());
        assertEquals(expectedSignaturesCount(), eaaWrappper.getEAASignatures().size());
        assertEquals(disclosuresPresent() || orphanSelectivelyDisclosableClaimsPresent(), Utils.isCollectionNotEmpty(eaaWrappper.getDigestMatchers()));
        assertEquals(keyBindingPresent(), eaaWrappper.getKeyBindingSignature() != null);
        assertEquals(getEAAType(), eaaWrappper.getEAAType());

        checkEAADigestMatchers(diagnosticData);
        checkClaims(diagnosticData);
        checkDeviceKeyClaim(diagnosticData);
        checkEAARevocations(diagnosticData);
    }

    protected void checkEAARevocations(DiagnosticData diagnosticData) {
        for (EAAWrapper eaa : diagnosticData.getAllEAA()) {
            for (EAARevocationWrapper eaaStatusWrapper : eaa.getEAARevocations()) {
                assertNotNull(eaaStatusWrapper.getId());
                assertNotNull(eaaStatusWrapper.getStatus());
            }
        }
    }

    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        for (EAAWrapper eaa : diagnosticData.getEAAs()) {
            for (XmlDigestMatcher digestMatcher : eaa.getDigestMatchers()) {
                if (orphanSelectivelyDisclosableClaimsPresent() && DigestMatcherType.EAA_ORPHAN_SELECTIVELY_DISCLOSABLE_CLAIM == digestMatcher.getType()) {
                    assertFalse(digestMatcher.isDataFound());
                    assertFalse(digestMatcher.isDataIntact());
                } else {
                    assertTrue(DigestMatcherType.EAA_DISCLOSURE == digestMatcher.getType() || DigestMatcherType.EAA_NESTED_DISCLOSURE == digestMatcher.getType());
                    assertTrue(digestMatcher.isDataFound());
                    assertTrue(digestMatcher.isDataIntact());
                    assertNotNull(digestMatcher.getDisclosableClaim());
                }
                if (EAAType.ISO_IEC_MDOC == eaa.getEAAType()) {
                    assertNotNull(digestMatcher.getDisclosableClaim().getId());
                    assertNotNull(digestMatcher.getDisclosableClaim().getNamespace());
                }
            }
        }
    }

    protected void checkClaims(DiagnosticData diagnosticData) {
        for (EAAWrapper eaa : diagnosticData.getEAAs()) {
            List<ClaimWrapper> eaaPayloadClaims = new ArrayList<>(eaa.getAllEAAPayloadClaims());
            assertTrue(Utils.isCollectionNotEmpty(eaaPayloadClaims));
            assertTrue(Utils.isCollectionNotEmpty(eaa.getAllEAAPayloadClaimNames()));
            checkClaimsRecursively(eaaPayloadClaims, true);
            for (ClaimWrapper claimWrapper : eaaPayloadClaims) {
                ClaimWrapper claimByHeaderName = eaa.getClaimByHeaderName(claimWrapper.getName());
                assertNotNull(claimByHeaderName);
                assertEquals(claimByHeaderName.getName(), claimWrapper.getName());
                assertEquals(claimByHeaderName.getNamespace(), claimWrapper.getNamespace());
                assertEquals(claimByHeaderName.getText(), claimWrapper.getText());
                assertEquals(claimByHeaderName.getNumber(), claimWrapper.getNumber());
                assertEquals(claimByHeaderName.getBoolean(), claimWrapper.getBoolean());
                assertArrayEquals(claimByHeaderName.getBinary(), claimWrapper.getBinary());
                if (claimWrapper.getDateTime() != null) {
                    assertNotNull(claimByHeaderName.getDateTime());
                    assertEquals(0, claimWrapper.getDateTime().compareTo(claimByHeaderName.getDateTime()));
                } else {
                    assertNull(claimByHeaderName.getDateTime());
                }
                if (claimWrapper.getList() != null) {
                    assertEquals(claimWrapper.getList().size(), claimByHeaderName.getList().size());
                } else {
                    assertNull(claimByHeaderName.getList());
                }
                if (claimWrapper.getMap() != null) {
                    assertNotNull(claimByHeaderName.getMap());
                    assertEquals(claimWrapper.getMap(), claimByHeaderName.getMap());
                } else {
                    assertNull(claimByHeaderName.getMap());
                }

                assertTrue(Utils.isStringNotEmpty(claimWrapper.getDisplayValue()));

                if (EAAType.ISO_IEC_MDOC == eaa.getEAAType() && claimWrapper.isSelectivelyDisclosable()) {
                    assertNotNull(claimWrapper.getNamespace());
                }
            }
            assertEquals(disclosuresPresent(), isDisclosureFound(eaaPayloadClaims));
            assertEquals(disclosuresPresent(), Utils.isCollectionNotEmpty(eaa.getSelectivelyDisclosableClaims()));
        }
    }

    protected void checkClaimsRecursively(Collection<ClaimWrapper> claims, boolean mapOrigin) {
        for (ClaimWrapper claimWrapper : claims) {
            assertEquals(claimWrapper.getName() != null, mapOrigin);

            assertTrue(claimWrapper.getText() != null || claimWrapper.getDateTime() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getText() != null, claimWrapper.getDateTime() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getDateTime() != null, claimWrapper.getText() != null ||
                    claimWrapper.getNumber() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getNumber() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(Utils.isCollectionNotEmpty(claimWrapper.getList()), claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || claimWrapper.getNumber() != null ||
                    claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getBoolean() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getBinary() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getMap() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.getMap() != null, claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNull(), claimWrapper.getText() != null ||
                    claimWrapper.getDateTime() != null || Utils.isCollectionNotEmpty(claimWrapper.getList()) ||
                    claimWrapper.getNumber() != null || claimWrapper.getBoolean() != null || claimWrapper.getBinary() != null || claimWrapper.getMap() != null);

            assertTrue(claimWrapper.isText() || claimWrapper.isDateTime() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isText(), claimWrapper.isDateTime() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isDateTime(), claimWrapper.isText() ||
                    claimWrapper.isNumber() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNumber(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isList(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isNumber() ||
                    claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isBoolean(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBinary() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isBinary(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isMap() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isMap(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isNull());
            assertNotEquals(claimWrapper.isNull(), claimWrapper.isText() ||
                    claimWrapper.isDateTime() || claimWrapper.isList() ||
                    claimWrapper.isNumber() || claimWrapper.isBoolean() || claimWrapper.isBinary() || claimWrapper.isMap());

            assertTrue(claimWrapper.isNull() || !claimWrapper.isEmpty());
            assertTrue(Utils.isStringNotEmpty(claimWrapper.getDisplayValue()));

            if (claimWrapper.getList() != null) {
                checkClaimsRecursively(claimWrapper.getList(), false);
            } else if (claimWrapper.getMap() != null) {
                checkClaimsRecursively(claimWrapper.getMap().values(), true);
            }
        }
    }

    protected boolean isDisclosureFound(Collection<ClaimWrapper> claims) {
        for (ClaimWrapper claimWrapper : claims) {
            if (claimWrapper.isSelectivelyDisclosable()) {
                return true;
            }
            if (claimWrapper.getList() != null) {
                if (isDisclosureFound(claimWrapper.getList())) {
                    return true;
                }
            } else if (claimWrapper.getMap() != null) {
                if (isDisclosureFound(claimWrapper.getMap().values())) {
                    return true;
                }
            }
        }
        return false;
    }

    protected void checkDeviceKeyClaim(DiagnosticData diagnosticData) {
        for (EAAWrapper eaa : diagnosticData.getEAAs()) {
            if (keyBindingPresent()) {
                assertNotNull(eaa.getEAADevicePublicKey());
                if (eaa.getEAADeviceCertificate() != null) {
                    assertEquals(1, eaa.getEAADeviceCertificateChain().size()); // only one certificate should be present
                }
            }
        }
    }

    protected void checkEAAStatusTokens(DiagnosticData diagnosticData) {
        for (EAARevocationTokenWrapper eaaRevocationTokenWrapper : diagnosticData.getAllEAARevocationTokens()) {
            assertNotNull(eaaRevocationTokenWrapper.getId());
            assertNotNull(eaaRevocationTokenWrapper.getType());
            assertNotNull(eaaRevocationTokenWrapper.getOrigin());
            assertNotNull(eaaRevocationTokenWrapper.getIssuedAt());
            assertNotNull(eaaRevocationTokenWrapper.getExpirationTime());

            assertNotNull(eaaRevocationTokenWrapper.foundCertificates());
            assertNotNull(eaaRevocationTokenWrapper.foundCertificates().getRelatedCertificates());
            assertNotNull(eaaRevocationTokenWrapper.foundCertificates().getOrphanCertificates());

            if (eaaRevocationTokenWrapper.getSigningCertificate() != null) {
                assertTrue(Utils.isCollectionNotEmpty(eaaRevocationTokenWrapper.getCertificateChain()));
            }
        }
    }

    protected int expectedSignaturesCount() {
        return 1;
    }

    protected boolean disclosuresPresent() {
        return true;
    }

    protected boolean orphanSelectivelyDisclosableClaimsPresent() {
        return false;
    }

    protected boolean keyBindingPresent() {
        return true;
    }

    protected abstract EAAType getEAAType();

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (!signatureWrapper.isKeyBindingSignature()) {
                assertTrue(signatureWrapper.isSigningCertificateIdentified());
                assertTrue(signatureWrapper.isSigningCertificateReferencePresent());
                assertTrue(signatureWrapper.isSigningCertificateReferenceUnique());

                CertificateRefWrapper signingCertificateReference = signatureWrapper.getSigningCertificateReference();
                assertNotNull(signingCertificateReference);
                assertTrue(signingCertificateReference.isDigestValuePresent());
                assertTrue(signingCertificateReference.isDigestValueMatch());
                if (signingCertificateReference.isIssuerSerialPresent()) {
                    assertTrue(signingCertificateReference.isIssuerSerialMatch());
                }

                CertificateWrapper signingCertificate = signatureWrapper.getSigningCertificate();
                assertNotNull(signingCertificate);
                String signingCertificateId = signingCertificate.getId();
                String certificateDN = diagnosticData.getCertificateDN(signingCertificateId);
                String certificateSerialNumber = diagnosticData.getCertificateSerialNumber(signingCertificateId);
                assertEquals(signingCertificate.getCertificateDN(), certificateDN);
                assertEquals(signingCertificate.getSerialNumber(), certificateSerialNumber);

                assertTrue(Utils.isCollectionEmpty(signatureWrapper.foundCertificates()
                        .getOrphanCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE)));

            } else {
                assertTrue(signatureWrapper.getSigningCertificate() != null || signatureWrapper.getSigningCertificatePublicKey() != null);
            }

        }
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        for (EAAWrapper eaa : diagnosticData.getEAAs()) {
            for (SignatureWrapper signatureWrapper : eaa.getEAASignatures()) {
                if (signatureWrapper.isSignatureValid()) {
                    assertEquals(1, Utils.collectionSize(signatureWrapper.getSignatureScopes()));
                    XmlSignatureScope signatureScope = signatureWrapper.getSignatureScopes().get(0);
                    assertNotNull(signatureScope.getScope());
                    assertNotNull(signatureScope.getSignerData());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
                    assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
                    assertEquals(SignatureScopeType.EAA_SIGNATURE, signatureScope.getScope());
                }
            }
            SignatureWrapper keyBindingSignature = eaa.getKeyBindingSignature();
            if (keyBindingSignature != null && keyBindingSignature.isSignatureValid()) {
                assertEquals(1, Utils.collectionSize(keyBindingSignature.getSignatureScopes()));
                XmlSignatureScope signatureScope = keyBindingSignature.getSignatureScopes().get(0);
                assertNotNull(signatureScope.getScope());
                assertNotNull(signatureScope.getSignerData());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestMethod());
                assertNotNull(signatureScope.getSignerData().getDigestAlgoAndValue().getDigestValue());
                assertEquals(SignatureScopeType.KEY_BINDING_SIGNATURE, signatureScope.getScope());
            }
        }
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanCertificateObjects()));
        // may include orphan certificate references (e.g. x5u)
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationObjects()));
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getAllOrphanRevocationReferences()));
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyDetailedReport(DetailedReport detailedReport) {
        assertNotNull(detailedReport);

        int nbBBBs = detailedReport.getBasicBuildingBlocksNumber();
        for (int i = 0; i < nbBBBs; i++) {
            String id = detailedReport.getBasicBuildingBlocksSignatureId(i);
            assertNotNull(id);

            Indication indication = detailedReport.getBasicBuildingBlocksIndication(id);
            assertNotNull(indication);
            if (!Indication.PASSED.equals(indication)) {
                SubIndication subIndication = detailedReport.getBasicBuildingBlocksSubIndication(id);
                assertNotNull(subIndication);
            }
        }

        List<String> eaaIds = detailedReport.getEAAIds();
        for (String eaaId : eaaIds) {
            XmlEAA xmlEAA = detailedReport.getXmlEAAById(eaaId);
            assertNotNull(xmlEAA);

            Indication indication = detailedReport.getEAAValidationIndication(eaaId);
            assertNotNull(indication);
            if (!Indication.PASSED.equals(indication)) {
                SubIndication subIndication = detailedReport.getEAAValidationSubIndication(eaaId);
                assertNotNull(subIndication);
            }
        }
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        List<String> eaaPresentationIdList = simpleReport.getEAAIdList();
        assertEquals(1, eaaPresentationIdList.size());

        assertEquals(eaaPresentationIdList.get(0), simpleReport.getFirstEAAId());

        String eaaPresentationId = simpleReport.getFirstEAAId();

        Indication indication = simpleReport.getIndication(eaaPresentationId);
        assertNotNull(indication);
        assertTrue(Indication.PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                || Indication.FAILED.equals(indication));
        if (Indication.PASSED.equals(indication)) {

            assertNull(simpleReport.getSubIndication(eaaPresentationId));
            assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(eaaPresentationId)));

        } else {
            SubIndication subIndication = simpleReport.getSubIndication(eaaPresentationId);
            assertNotNull(subIndication);
            assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(eaaPresentationId)));
        }
        assertNotNull(simpleReport.getEAAQualification(eaaPresentationId));

        List<XmlSignature> eaaSignatures = simpleReport.getEAASignatures(eaaPresentationId);
        assertEquals(expectedSignaturesCount(), eaaSignatures.size());
        for (XmlSignature xmlSignature : eaaSignatures) {
            verifySimpleReportSignature(simpleReport, xmlSignature);
        }

        XmlSignature keyBindingSignature = simpleReport.getEAAKeyBindingSignature(eaaPresentationId);
        assertEquals(keyBindingPresent(), keyBindingSignature != null);
        if (keyBindingSignature != null) {
            verifySimpleReportSignature(simpleReport, keyBindingSignature);
        }
    }

    private void verifySimpleReportSignature(SimpleReport simpleReport, XmlSignature xmlSignature) {
        String sigId = xmlSignature.getId();

        Indication indication = simpleReport.getIndication(sigId);
        assertNotNull(indication);
        assertTrue(Indication.TOTAL_PASSED.equals(indication) || Indication.INDETERMINATE.equals(indication)
                || Indication.TOTAL_FAILED.equals(indication));
        if (Indication.TOTAL_PASSED.equals(indication)) {
            assertTrue(Utils.isCollectionNotEmpty(simpleReport.getSignatureScopes(sigId)));

            assertNull(simpleReport.getSubIndication(sigId));
            assertTrue(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));

            if (!createdWithTrustAnchor(simpleReport.getCertificateChain(sigId))
                    && !timestampedWithTrustAnchor(simpleReport.getSignatureTimestamps(sigId))
                    && !preservedByERWithTrustAnchor(simpleReport.getSignatureEvidenceRecords(sigId))
                    && Utils.isStringNotEmpty(simpleReport.getSignedBy(sigId))) {
                assertNotNull(simpleReport.getExtensionPeriodMax(sigId));
            }

        } else {
            SubIndication subIndication = simpleReport.getSubIndication(sigId);
            assertNotNull(subIndication);
            assertFalse(Utils.isCollectionEmpty(simpleReport.getAdESValidationErrors(sigId)));
        }
        assertNotNull(simpleReport.getSignatureQualification(sigId));

        List<eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp> signatureTimestamps = simpleReport.getSignatureTimestamps(sigId);
        for (eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp xmlTimestamp : signatureTimestamps) {
            String tstId = xmlTimestamp.getId();
            assertNotNull(tstId);

            Indication timestampIndication = simpleReport.getIndication(tstId);
            assertNotNull(timestampIndication);
            assertTrue(Indication.PASSED.equals(timestampIndication) || Indication.INDETERMINATE.equals(timestampIndication)
                    || Indication.FAILED.equals(timestampIndication));
            if (timestampIndication != Indication.PASSED) {
                assertNotNull(simpleReport.getSubIndication(tstId));
                assertTrue(Utils.isCollectionNotEmpty(simpleReport.getAdESValidationErrors(tstId)));
            }
            assertNotNull(simpleReport.getTimestampQualification(tstId));
        }

    }

}

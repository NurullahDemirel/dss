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
package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.COSEHeaderParameter;
import eu.europa.esig.dss.cbades.COSEProtectedHeader;
import eu.europa.esig.dss.cbades.COSESign;
import eu.europa.esig.dss.cbades.COSESign1;
import eu.europa.esig.dss.cbades.COSEUnprotectedHeader;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.cbades.validation.CBAdESSignature;
import eu.europa.esig.dss.cbades.validation.CBAdESUHeaders;
import eu.europa.esig.dss.cbades.validation.CBORSignature;
import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeCodeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.eaa.common.creation.EAAStatusList;
import eu.europa.esig.dss.eaa.common.validation.AbstractEAAPresentationTestIssuance;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.eaa.mdoc.validation.MdocDeviceResponseEAAPresentationValidator;
import eu.europa.esig.dss.eaa.mdoc.validation.MdocValidationParameters;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.enumerations.COSEStructureType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EAAPresentationType;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.enumerations.EllipticCurve;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.x509.BaselineBCertificateSelector;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractMdocEAAPresentationTestIssuance extends AbstractEAAPresentationTestIssuance
        <CBAdESSignatureParameters, MdocEAAPayloadParameters, MdocEAAClaim, MdocEAADisclosure, MdocKeyBindingParameters> {

    @Override
    protected MdocEAAService getService() {
        return new MdocEAAService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument issuePresentation(DSSDocument signedEAA, List<MdocEAADisclosure> disclosures, DSSDocument keyBindingSignature) {
        if (includeKeyBindingSignature()) {
            return getService().issuePresentation(signedEAA, disclosures, keyBindingSignature, getKeyBindingParameters());
        } else {
            return getService().createIssuerSigned(signedEAA, disclosures);
        }
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.CBOR;
    }

    @Override
    protected EAAType getEAAType() {
        return EAAType.ISO_IEC_MDOC;
    }

    @Override
    protected EAAPresentationType getEAAPresentationType() {
        if (keyBindingPresent()) {
            return EAAPresentationType.MDOC_DEVICE_RESPONSE;
        } else {
            return EAAPresentationType.MDOC_ISSUER_SIGNED;
        }
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        if (keyBindingPresent()) {
            MdocDeviceResponseEAAPresentationValidator mdocValidator = assertInstanceOf(MdocDeviceResponseEAAPresentationValidator.class, validator);
            MdocValidationParameters mdocValidationParameters = new MdocValidationParameters();
            mdocValidationParameters.setSessionTranscript(buildSessionTranscript());
            mdocValidator.setEAAValidationParameters(mdocValidationParameters);
        }
        return validator;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            assertInstanceOf(CBAdESSignature.class, signature);
            CBAdESSignature cbadesSignature = (CBAdESSignature) signature;

            CBORSignature cose = cbadesSignature.getCoseSignature();

            CBAdESUHeaders cbAdESUHeaders = new CBAdESUHeaders(cose);
            assertFalse(cbAdESUHeaders.isExist());

            assertNotNull(cose.getContext());
            assertEquals(COSESignatureType.COSE_SIGN1, cose.getContext());

            assertNotNull(cose.getCoseSignStructure());
            assertEquals(COSEStructureType.COSE_SIGN == getSignatureParameters().getCoseStructureType(),
                    cose.getCoseSignStructure() instanceof COSESign);
            assertInstanceOf(COSESign1.class, cose.getCoseSignStructure());

            assertFalse(cose.isTagged());

            COSEProtectedHeader bodyProtectedHeader = cose.getBodyProtectedHeader();
            COSEProtectedHeader signerProtectedHeader = cose.getSignerProtectedHeader();

            COSEUnprotectedHeader bodyUnprotectedHeader = cose.getBodyUnprotectedHeader();
            COSEUnprotectedHeader signerUnprotectedHeader = cose.getSignerUnprotectedHeader();

            assertNotNull(bodyProtectedHeader);
            assertFalse(bodyProtectedHeader.isEmpty());
            assertNull(signerProtectedHeader);

            assertNotNull(bodyUnprotectedHeader);
            if (signature.isKeyBindingSignature()) {
                assertTrue(bodyUnprotectedHeader.isEmpty());
            } else {
                assertFalse(bodyUnprotectedHeader.isEmpty());
            }
            assertNull(signerUnprotectedHeader);

            Set<CBORObject> keySet = bodyProtectedHeader.getKeys();
            assertTrue(Utils.isCollectionNotEmpty(keySet));
            for (CBORObject signedPropertyKey : keySet) {
                assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyKey));
            }

            CBORObject crit = bodyProtectedHeader.getHeader(COSEHeaderParameter.CRIT.cbor());
            if (crit != null) {
                assertTrue(crit.isArray());
                assertInstanceOf(CBORArray.class, crit);

                CBORArray critArray = (CBORArray) crit;
                assertFalse(critArray.isEmpty());
                for (CBORObject critItem : critArray.getValueAsList()) {
                    assertTrue(critItem.isUnsignedInteger() || critItem.isNegativeInteger());
                    assertInstanceOf(CBORSimpleObject.class, critItem);

                    Long labelId = critItem.getValueAsLong();
                    assertNotNull(labelId);

                    assertTrue(CBORUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
                    assertTrue(CBORUtils.isRequiredCriticalHeader(critItem));
                }
            }

        }
    }

    @Override
    protected void checkEAADigestMatchers(DiagnosticData diagnosticData) {
        super.checkEAADigestMatchers(diagnosticData);

        for (EAAWrapper eaa : diagnosticData.getEAAs()) {
            for (XmlDigestMatcher xmlDigestMatcher : eaa.getDigestMatchers()) {
                if (DigestMatcherType.EAA_DISCLOSURE == xmlDigestMatcher.getType()) {
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getName());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getNamespace());
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getId());
                }
            }
        }
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        for (EAAWrapper eaa : diagnosticData.getEAAs()) {

            assertNotNull(eaa.getEAAVersion());
            assertNotNull(eaa.getEAADocumentType());
            assertNotNull(eaa.getDigestAlgorithm());
            assertNotNull(eaa.getEAADevicePublicKey());
            assertNotNull(eaa.getEAAIssuedAt());
            assertNotNull(eaa.getEAANotBefore());
            assertNotNull(eaa.getEAAExpiration());

            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getDocumentType())) {
                assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentType(), eaa.getDocumentType());
            } else {
                assertNull(eaa.getDocumentType());
            }

            assertEquals(getPayloadParameters().getVersion(), eaa.getEAAVersion());
            assertEquals(getPayloadParameters().getDocType(), eaa.getEAADocumentType());
            assertTrue(eaa.getDigestMatchers().stream().allMatch(m -> getPayloadParameters().getDigestAlgorithm() == m.getDigestMethod()));
            assertArrayEquals(getPayloadParameters().getDeviceKey().getEncoded(), eaa.getEAADevicePublicKey());
            if (Utils.isCollectionNotEmpty(getPayloadParameters().getKeyAuthorizationsNamespaces())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsNamespaces(), eaa.getEAADeviceKeyAuthorizedNamespaces());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(eaa.getEAADeviceKeyAuthorizedNamespaces()));
            }
            if (Utils.isMapNotEmpty(getPayloadParameters().getKeyAuthorizationsDataElements())) {
                assertEquals(getPayloadParameters().getKeyAuthorizationsDataElements(), eaa.getEAADeviceKeyAuthorizedDataElements());
            } else {
                assertFalse(Utils.isMapNotEmpty(eaa.getEAADeviceKeyAuthorizedDataElements()));
            }
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getSigned()), DSSUtils.formatDateToRFC(eaa.getEAAIssuedAt()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidFrom()), DSSUtils.formatDateToRFC(eaa.getEAANotBefore()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getValidUntil()), DSSUtils.formatDateToRFC(eaa.getEAAExpiration()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getExpectedUpdate()), DSSUtils.formatDateToRFC(eaa.getEAANextUpdate()));

            assertStatusListEqual(getPayloadParameters().getStatusList(), eaa);
            assertIdentifierListEqual(getPayloadParameters().getIdentifierList(), eaa);

            assertEquals(getPayloadParameters().getCategory(), eaa.getEAACategory());
            assertEquals(Utils.isTrue(getPayloadParameters().isShortLived()), Utils.isTrue(eaa.getShortLived()));
            assertEquals(Utils.isTrue(getPayloadParameters().isOneTime()), Utils.isTrue(eaa.getOneTimeUse()));

            assertEquals(getPayloadParameters().selectivelyDisclosable().getGivenName(), eaa.getHolderGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getFamilyName(), eaa.getHolderFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEmail(), eaa.getHolderEmail());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getSex(), eaa.getHolderGender());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getBirthdate()), DSSUtils.formatDateToRFC(eaa.getHolderBirthdate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPhoneNumber(), eaa.getHolderPhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirth(), eaa.getHolderPlaceOfBirth());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthCountry(), eaa.getHolderPlaceOfBirthCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthLocality(), eaa.getHolderPlaceOfBirthCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPlaceOfBirthRegion(), eaa.getHolderPlaceOfBirthRegion());
            if (Utils.isStringNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationality())) {
                assertTrue(Utils.isCollectionNotEmpty(eaa.getHolderNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationality(), eaa.getHolderNationalities().get(0));
            } else if (Utils.isCollectionNotEmpty(getPayloadParameters().selectivelyDisclosable().getNationalities())) {
                assertTrue(Utils.isCollectionNotEmpty(eaa.getHolderNationalities()));
                assertEquals(getPayloadParameters().selectivelyDisclosable().getNationalities(), eaa.getHolderNationalities());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(eaa.getHolderNationalities()));
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthGivenName(), eaa.getHolderBirthGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFamilyName(), eaa.getHolderBirthFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTitle(), eaa.getHolderTitle());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getMobilePhoneNumber(), eaa.getHolderMobilePhoneNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPseudonym(), eaa.getHolderPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingCountry(), eaa.getDocumentIssuingAuthorityCountry());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthority(), eaa.getDocumentIssuingAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDocumentNumber(), eaa.getDocumentNumber());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getPortrait(), eaa.getHolderPortrait());
            assertDrivingPrivilegesEquals(getPayloadParameters().selectivelyDisclosable().getDrivingPrivileges(), eaa.getHolderDrivingPrivileges());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getDistinguishingSign(), eaa.getDocumentIssuingAuthorityCountryUNDistinguishingSign());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPersonalAdministrativeNumber(), eaa.getPersonalAdministrativeNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHeight(), eaa.getHolderHeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getWeight(), eaa.getHolderWeight());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getEyeColour(), eaa.getHolderEyeColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getHairColour(), eaa.getHolderHairColour());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPostalAddress(), eaa.getResidentPostalAddress());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getPortraitCaptureDate(), eaa.getHolderPortraitCaptureDate());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeInYears(), eaa.getHolderAgeInYears());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAgeBirthYear(), eaa.getHolderAgeBirthYear());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getAgeOverNN())) {
                for (Map.Entry<Integer, Boolean> ageEntry : getPayloadParameters().selectivelyDisclosable().getAgeOverNN().entrySet()) {
                    assertEquals(ageEntry.getValue(), eaa.isHolderAgeOver(ageEntry.getKey()));
                }
            }
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingJurisdiction(), eaa.getDocumentIssuingAuthorityJurisdiction());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCity(), eaa.getResidentAddressCity());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressState(), eaa.getResidentAddressState());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressPostalCode(), eaa.getResidentAddressPostalCode());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressCountry(), eaa.getResidentAddressCountry());
            if (Utils.isMapNotEmpty(getPayloadParameters().selectivelyDisclosable().getBiometricTemplate())) {
                for (Map.Entry<String, byte[]> bioEntry : getPayloadParameters().selectivelyDisclosable().getBiometricTemplate().entrySet()) {
                    assertArrayEquals(bioEntry.getValue(), eaa.getHolderBiometricTemplate(bioEntry.getKey()));
                }
            }
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getBiometricTemplateFace(), eaa.getHolderBiometricTemplate("face"));
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getSignatureUsualMark(), eaa.getHolderSignatureUsualMark());
            assertArrayEquals(getPayloadParameters().selectivelyDisclosable().getFingerprint(), eaa.getHolderFingerprint());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBusinessName(), eaa.getHolderBusinessName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getOrganizationName(), eaa.getHolderOrganizationName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getBirthFullName(), eaa.getHolderBirthFullName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getProfession(), eaa.getHolderProfession());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFather(), eaa.getHolderRelationshipFather());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMother(), eaa.getHolderRelationshipMother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParent(), eaa.getHolderRelationshipParent());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSon(), eaa.getHolderRelationshipSon());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughter(), eaa.getHolderRelationshipDaughter());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipBrother(), eaa.getHolderRelationshipBrother());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSister(), eaa.getHolderRelationshipSister());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSibling(), eaa.getHolderRelationshipSibling());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSpouse(), eaa.getHolderRelationshipSpouse());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipFatherInLaw(), eaa.getHolderRelationshipFatherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipMotherInLaw(), eaa.getHolderRelationshipMotherInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentInLaw(), eaa.getHolderRelationshipParentInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipSonInLaw(), eaa.getHolderRelationshipSonInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipDaughterInLaw(), eaa.getHolderRelationshipDaughterInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipChildInLaw(), eaa.getHolderRelationshipChildInLaw());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipParentalAuthority(), eaa.getHolderRelationshipParentalAuthority());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipLegalRepresentative(), eaa.getHolderRelationshipLegalRepresentative());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getRelationshipAgent(), eaa.getHolderRelationshipAgent());
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeIssuanceDate()), DSSUtils.formatDateToRFC(eaa.getAdministrativeIssuanceDate()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().selectivelyDisclosable().getAdministrativeExpirationDate()), DSSUtils.formatDateToRFC(eaa.getAdministrativeExpirationDate()));
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressStreet(), eaa.getResidentAddressStreet());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAddressHouseNumber(), eaa.getResidentAddressHouseNumber());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getTrustAnchor(), eaa.getTrustAnchor());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getIssuingAuthorityRegistrationIdentifier(), eaa.getIssuingRegistrationIdentifier());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectGivenName(), eaa.getAttestedAttributesSubjectGivenName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectFamilyName(), eaa.getAttestedAttributesSubjectFamilyName());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectPseudonym(), eaa.getAttestedAttributesSubjectPseudonym());
            assertEquals(getPayloadParameters().selectivelyDisclosable().getAttestedAttributesSubjectDocumentNumber(), eaa.getAttestedAttributesSubjectDocumentNumber());
        }
    }

    protected void assertDrivingPrivilegesEquals(List<MdocDrivingPrivilege> drivingPrivileges, DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper) {
        if (Utils.isCollectionNotEmpty(drivingPrivileges)) {
            assertNotNull(drivingPrivilegesClaimWrapper);
            assertEquals(drivingPrivileges.size(), drivingPrivilegesClaimWrapper.getDrivingPrivileges().size());
            for (int i = 0; i < drivingPrivileges.size(); i++) {
                MdocDrivingPrivilege mdocDrivingPrivilege = drivingPrivileges.get(i);
                DrivingPrivilegeClaimWrapper drivingPrivilegeClaimWrapper = drivingPrivilegesClaimWrapper.getDrivingPrivileges().get(i);
                assertEquals(mdocDrivingPrivilege.getVehicleCategoryCode(), drivingPrivilegeClaimWrapper.getVehicleCategoryCode().getText());
                if (mdocDrivingPrivilege.getIssueDate() != null) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getIssueDate());
                    assertEquals(mdocDrivingPrivilege.getIssueDate(), drivingPrivilegeClaimWrapper.getIssueDate().getDateTime());
                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getIssueDate());
                }
                if (mdocDrivingPrivilege.getExpiryDate() != null) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getExpiryDate());
                    assertEquals(mdocDrivingPrivilege.getExpiryDate(), drivingPrivilegeClaimWrapper.getExpiryDate().getDateTime());
                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getExpiryDate());
                }
                if (Utils.isCollectionNotEmpty(mdocDrivingPrivilege.getCodes())) {
                    assertNotNull(drivingPrivilegeClaimWrapper.getCodes());
                    for (int j = 0; j < mdocDrivingPrivilege.getCodes().size(); j++) {
                        MdocDrivingPrivilege.Code code = mdocDrivingPrivilege.getCodes().get(j);
                        DrivingPrivilegeCodeClaimWrapper codeWrapper = drivingPrivilegeClaimWrapper.getCodes().getCodes().get(j);
                        assertEquals(code.getCode(), codeWrapper.getCode().getText());
                        if (Utils.isStringNotEmpty(code.getSign())) {
                            assertNotNull(codeWrapper.getSign());
                            assertEquals(code.getSign(), codeWrapper.getSign().getText());
                        } else {
                            assertNull(codeWrapper.getSign());
                        }
                        if (Utils.isStringNotEmpty(code.getValue())) {
                            assertNotNull(codeWrapper.getValue());
                            assertEquals(code.getValue(), codeWrapper.getValue().getText());
                        } else {
                            assertNull(codeWrapper.getValue());
                        }
                    }

                } else {
                    assertNull(drivingPrivilegeClaimWrapper.getCodes());
                }

            }

        } else {
            assertNull(drivingPrivilegesClaimWrapper);
        }
    }

    private void assertStatusListEqual(EAAStatusList statusList, EAAWrapper eaa) {
        if (statusList != null) {
            assertEquals(statusList.getIndex(), eaa.getEAAStatusIndex());
            assertEquals(statusList.getUri(), eaa.getEAAStatusUri());
            if (statusList.getCertificate() != null) {
                assertArrayEquals(statusList.getCertificate().getEncoded(), eaa.getEAAStatusCertificate());
            } else {
                assertNull(eaa.getEAAStatusCertificate());
            }
        } else {
            assertNull(eaa.getEAAStatusIndex());
            assertNull(eaa.getEAAStatusUri());
            assertNull(eaa.getEAAStatusCertificate());
        }
    }

    private void assertIdentifierListEqual(MdocIdentifierList identifierList, EAAWrapper eaa) {
        if (identifierList != null) {
            assertArrayEquals(identifierList.getIdentifier(), eaa.getEAAIdentifierListId());
            assertEquals(identifierList.getUri(), eaa.getEAAIdentifierListUri());
            if (identifierList.getCertificate() != null) {
                assertArrayEquals(identifierList.getCertificate().getEncoded(), eaa.getEAAIdentifierListCertificate());
            } else {
                assertNull(eaa.getEAAIdentifierListCertificate());
            }
        } else {
            assertNull(eaa.getEAAIdentifierListId());
            assertNull(eaa.getEAAIdentifierListUri());
            assertNull(eaa.getEAAIdentifierListCertificate());
        }
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        super.checkStructureValidation(diagnosticData);

        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            COSESignatureType coseSignatureType = signature.getCOSESignatureType();
            assertNotNull(coseSignatureType);
            assertEquals(COSESignatureType.COSE_SIGN1, coseSignatureType);
            assertFalse(signature.isCOSETagged());
            assertFalse(signature.isCounterSignature());
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertTrue(signatureWrapper.isSigningCertificateIdentified());
            assertTrue(signatureWrapper.isSigningCertificateReferencePresent());

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

            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);

            CBAdESSignatureParameters signatureParameters = signatureWrapper.isKeyBindingSignature() ? getKeyBindingSignatureParameters() : getSignatureParameters();
            if (signatureParameters.isIncludeCertificateChainThumbprints()) {
                BaselineBCertificateSelector certificateSelector = new BaselineBCertificateSelector(
                        signatureParameters.getSigningCertificate(), signatureParameters.getCertificateChain())
                        .setTrustAnchorBPPolicy(signatureParameters.bLevel().isTrustAnchorBPPolicy())
                        .setTrustedCertificateSource(getTrustedCertificateSource());
                assertEquals(certificateSelector.getCertificates().size(), signingCertificates.size());
            } else {
                assertEquals(1, signingCertificates.size());
            }

            List<CertificateRefWrapper> signingCertificateRefs = null;
            for (RelatedCertificateWrapper certificateWrapper : signingCertificates) {
                if (signatureWrapper.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                    signingCertificateRefs = certificateWrapper.getReferences();
                    break;
                }
            }
            assertNotNull(signingCertificateRefs);

            List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
            List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

            int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
            assertEquals(signCertRefs, signingCertificateRefs.size());

            if (signatureParameters.isIncludeKeyIdentifier()) {
                assertEquals(1, kidCerts.size());
            } else if (Utils.isStringNotEmpty(signatureParameters.getX509Url())) {
                assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
            } else {
                assertEquals(0, kidCerts.size());
                assertEquals(0, x5uCerts.size());
            }

            for (CertificateRefWrapper certificateRef : signingCertificateRefs) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getDigestAlgoAndValue());
                    assertNotNull(certificateRef.getDigestMethod());
                    assertTrue(certificateRef.isDigestValuePresent());
                    assertTrue(certificateRef.isDigestValueMatch());
                    assertNull(certificateRef.getIssuerSerial());

                } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    if (certificateRef.getIssuerSerial() != null) {
                        assertNotNull(certificateRef.getIssuerSerial());
                        assertTrue(certificateRef.isIssuerSerialPresent());
                        assertTrue(certificateRef.isIssuerSerialMatch());
                    } else {
                        assertNotNull(certificateRef.getKid());
                    }
                    assertNull(certificateRef.getDigestAlgoAndValue());

                } else if (CertificateRefOrigin.X509_URL.equals(certificateRef.getOrigin())) {
                    assertNotNull(certificateRef.getCertificateId());
                    assertNotNull(certificateRef.getX509Url());
                }
            }
        }
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        super.checkCertificates(diagnosticData);

        for (EAAWrapper eaaWrapper : diagnosticData.getEAAs()) {
            for (SignatureWrapper signature : eaaWrapper.getEAASignatures()) {
                assertFalse(signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.UNPROTECTED_HEADER).isEmpty());
            }
        }
    }

    protected DSSDocument buildSessionTranscript() {
        byte[] select = new byte[]{0x01, 0x02};
        byte[] request = new byte[]{0x03, 0x04};
        SessionTranscriptBuilder builder =
                SessionTranscriptBuilder.nfcHandover(select, request)
                        .security(EllipticCurve.P_256, getSigningCert().getPublicKey())
                        .eReaderKey(getSigningCert().getPublicKey());

        return builder.build();
    }

}

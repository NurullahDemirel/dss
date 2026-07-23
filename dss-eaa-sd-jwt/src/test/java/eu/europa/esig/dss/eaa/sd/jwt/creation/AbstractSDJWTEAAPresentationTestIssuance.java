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
package eu.europa.esig.dss.eaa.sd.jwt.creation;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.eaa.common.creation.EAAStatusList;
import eu.europa.esig.dss.eaa.common.validation.AbstractEAAPresentationTestIssuance;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EAAPresentationType;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.enumerations.MimeType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.jades.JAdESHeaderParameterNames;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.validation.JAdESSignature;
import eu.europa.esig.dss.jades.validation.JWS;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.Headers;

import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public abstract class AbstractSDJWTEAAPresentationTestIssuance extends AbstractEAAPresentationTestIssuance<
        JAdESSignatureParameters, SDJWTEAAPayloadParameters, SDJWTEAAClaim, SDJWTEAADisclosure, SDJWTKeyBindingParameters> {

    @Override
    protected SDJWTEAAService getService() {
        return new SDJWTEAAService(getOfflineCertificateVerifier());
    }

    @Override
    protected MimeType getExpectedMime() {
        return MimeTypeEnum.JSON;
    }

    @Override
    protected EAAType getEAAType() {
        return EAAType.SD_JWT_VC;
    }

    @Override
    protected EAAPresentationType getEAAPresentationType() {
        return EAAPresentationType.SD_JWT;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void checkAdvancedSignatures(List<AdvancedSignature> signatures) {
        super.checkAdvancedSignatures(signatures);

        for (AdvancedSignature signature : signatures) {
            assertInstanceOf(JAdESSignature.class, signature);

            JAdESSignature jadesSignature = (JAdESSignature) signature;
            if (signature.isKeyBindingSignature()) {
                assertEquals(MimeTypeEnum.KB_JWT.getMimeTypeString(), jadesSignature.getSignatureType());
            } else {
                assertEquals(MimeTypeEnum.SD_JWT_VC.getMimeTypeString(), jadesSignature.getSignatureType());
            }

            JWS jws = jadesSignature.getJws();

            List<Object> etsiU = DSSJsonUtils.getEtsiU(jws);
            assertTrue(Utils.isCollectionEmpty(etsiU));

            Headers headers = jws.getHeaders();
            Set<String> keySet = DSSJsonUtils.extractJOSEHeaderMembersSet(jws);
            assertTrue(Utils.isCollectionNotEmpty(keySet));
            for (String signedPropertyName : keySet) {
                assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(signedPropertyName) ||
                        DSSJsonUtils.isCriticalHeaderException(signedPropertyName) ||
                        JAdESHeaderParameterNames.ETSI_U.equals(signedPropertyName) ||
                        SDJWTConstants.DISCLOSURES.equals(signedPropertyName) ||
                        SDJWTConstants.KB_JWT.equals(signedPropertyName));
            }

            Object crit = headers.getObjectHeaderValue(HeaderParameterNames.CRITICAL);
            if (crit != null) {
                assertInstanceOf(List.class, crit);

                List<String> critArray = (List<String>) crit;
                assertTrue(Utils.isCollectionNotEmpty(critArray));
                for (String critItem : critArray) {
                    assertTrue(DSSJsonUtils.getSupportedProtectedCriticalHeaders().contains(critItem));
                    assertTrue(DSSJsonUtils.isRequiredCriticalHeader(critItem));
                    assertFalse(DSSJsonUtils.isCriticalHeaderException(critItem));
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
                    assertNotNull(xmlDigestMatcher.getDisclosableClaim().getValue());
                    assertNull(xmlDigestMatcher.getDisclosableClaim().getNamespace());
                    assertNull(xmlDigestMatcher.getDisclosableClaim().getId());
                }
            }
        }
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        for (EAAWrapper eaa : diagnosticData.getEAAs()) {

            assertNotNull(eaa.getEAANotBefore());
            assertNotNull(eaa.getEAAExpiration());

            assertEquals(getPayloadParameters().getIssuer(), eaa.getEAAIssuer());
            // TODO : deviceKeyType
            // assertEquals(getPayloadParameters().getDeviceKeyType(), eaa.getDeviceKeyType());

            if (getPayloadParameters().getDeviceKey() != null) {
                assertArrayEquals(getPayloadParameters().getDeviceKey().getEncoded(), eaa.getEAADevicePublicKey());
            } else {
                assertNull(eaa.getEAADevicePublicKey());
            }

            if (Utils.isCollectionNotEmpty(getPayloadParameters().getDeviceX509CertificateChain())) {
                assertNotNull(eaa.getEAADeviceCertificateChain());
                assertEquals(getPayloadParameters().getDeviceX509CertificateChain().size(), eaa.getEAADeviceCertificateChain().size());
            } else {
                assertFalse(Utils.isCollectionNotEmpty(eaa.getEAADeviceCertificateChain()));
            }

            if (getPayloadParameters().getDeviceX509CertificateThumbprint() != null) {
                assertEquals(1, Utils.collectionSize(eaa.getEAADeviceCertificateChainDigests()));
                assertEquals(getPayloadParameters().getDeviceX509CertificateThumbprint().getAlgorithm(),
                        eaa.getEAADeviceCertificateChainDigests().get(0).getDigestMethod());
                assertArrayEquals(getPayloadParameters().getDeviceX509CertificateThumbprint().getValue(),
                        eaa.getEAADeviceCertificateChainDigests().get(0).getDigestValue());
            } else {
                assertEquals(0, Utils.collectionSize(eaa.getEAADeviceCertificateChainDigests()));
            }

            if (getPayloadParameters().getDeviceX509CertificateUrl() != null) {
                assertEquals(1, Utils.collectionSize(eaa.getEAADeviceCertificateUrls()));
                assertEquals(getPayloadParameters().getDeviceX509CertificateUrl(), eaa.getEAADeviceCertificateUrls().get(0));
            } else {
                assertEquals(0, Utils.collectionSize(eaa.getEAADeviceCertificateUrls()));
            }

            // TODO : not yet supported
            assertEquals(0, Utils.collectionSize(eaa.getEAADeviceCertificateKIDs()));

            assertEquals(getPayloadParameters().getVerifiableCredentialsType(), eaa.getEAAVerifiableCredentialsTypeUri());

            if (getPayloadParameters().getVerifiableCredentialsTypeIntegrity() != null) {
                assertEquals(getPayloadParameters().getVerifiableCredentialsTypeIntegrity().getAlgorithm(), eaa.getEAAVerifiableCredentialsTypeIntegrityDigestAlgorithm());
                assertArrayEquals(getPayloadParameters().getVerifiableCredentialsTypeIntegrity().getValue(), eaa.getEAAVerifiableCredentialsTypeIntegrityBytes());
            } else {
                assertNull(eaa.getEAAVerifiableCredentialsTypeIntegrityDigestAlgorithm());
                assertNull(eaa.getEAAVerifiableCredentialsTypeIntegrityBytes());
            }

            assertEquals(getPayloadParameters().getDigestAlgorithm(), eaa.getSelectiveDisclosuresDigestAlgorithm());

            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getNotBeforeDate()), DSSUtils.formatDateToRFC(eaa.getEAANotBefore()));
            assertEquals(DSSUtils.formatDateToRFC(getPayloadParameters().getExpirationDate()), DSSUtils.formatDateToRFC(eaa.getEAAExpiration()));

            assertStatusListEqual(getPayloadParameters().getStatusList(), eaa);

            assertEquals(getPayloadParameters().getCategory(), eaa.getEAACategory());
            assertEquals(Utils.isTrue(getPayloadParameters().isShortLived()), Utils.isTrue(eaa.getShortLived()));
            assertEquals(Utils.isTrue(getPayloadParameters().isOneTime()), Utils.isTrue(eaa.getOneTimeUse()));

            assertSDJWTClaims(getPayloadParameters().selectivelyDisclosable(), getPayloadParameters().nonSelectivelyDisclosable(), eaa);
        }
    }

    protected void assertStatusListEqual(EAAStatusList statusList, EAAWrapper eaa) {
        if (statusList != null) {
            if (statusList instanceof ETSIEAAStatusList) {
                ETSIEAAStatusList etsiEAAStatusList = (ETSIEAAStatusList) statusList;
                assertEquals(etsiEAAStatusList.getType(), eaa.getEAAStatusType());
                assertEquals(etsiEAAStatusList.getPurpose(), eaa.getEAAStatusPurpose());
            } else {
                assertNull(eaa.getEAAStatusType());
                assertNull(eaa.getEAAStatusPurpose());
            }
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

    protected void assertSDJWTClaims(SDJWTClaimParameters sd, SDJWTClaimParameters nonSd, EAAWrapper eaa) {

        assertEitherDate(sd.getIssuanceDate(), nonSd.getIssuanceDate(), eaa.getEAAIssuedAt());
        assertEither(sd.getSubject(), nonSd.getSubject(), eaa.getEAASubject());

        assertEither(sd.getGivenName(), nonSd.getGivenName(), eaa.getGivenName());
        assertEither(sd.getFamilyName(), nonSd.getFamilyName(), eaa.getFamilyName());
        assertEither(sd.getEmail(), nonSd.getEmail(), eaa.getEmail());
        assertEither(sd.getPhoneNumber(), nonSd.getPhoneNumber(), eaa.getPhoneNumber());
        assertEither(sd.getPhoneNumberVerified(), nonSd.getPhoneNumberVerified(), eaa.getPhoneNumberVerified());
        assertEitherDate(sd.getBirthdate(), nonSd.getBirthdate(), eaa.getBirthdate());

        assertEither(sd.getNationalities(), nonSd.getNationalities(), eaa.getNationalities());

        assertEither(sd.getPostalAddress(), nonSd.getPostalAddress(), eaa.getResidentPostalAddress());
        assertEither(sd.getAddressHouseNumber(), nonSd.getAddressHouseNumber(), eaa.getResidentAddressHouseNumber());
        assertEither(sd.getAddressStreet(), nonSd.getAddressStreet(), eaa.getResidentAddressStreet());
        assertEither(sd.getAddressCity(), nonSd.getAddressCity(), eaa.getResidentAddressCity());
        assertEither(sd.getAddressState(), nonSd.getAddressState(), eaa.getResidentAddressState());
        assertEither(sd.getAddressPostalCode(), nonSd.getAddressPostalCode(), eaa.getResidentAddressPostalCode());
        assertEither(sd.getAddressCountry(), nonSd.getAddressCountry(), eaa.getResidentAddressCountry());

        assertEither(sd.getPlaceOfBirthCountry(), nonSd.getPlaceOfBirthCountry(), eaa.getPlaceOfBirth());
        assertEither(sd.getPlaceOfBirthRegion(), nonSd.getPlaceOfBirthRegion(), eaa.getPlaceOfBirthRegion());
        assertEither(sd.getPlaceOfBirthLocality(), nonSd.getPlaceOfBirthLocality(), eaa.getPlaceOfBirthCity());

        assertEither(sd.getBirthGivenName(), nonSd.getBirthGivenName(), eaa.getBirthGivenName());
        assertEither(sd.getBirthFamilyName(), nonSd.getBirthFamilyName(), eaa.getBirthFamilyName());
        assertEither(sd.getTitle(), nonSd.getTitle(), eaa.getTitle());
        assertEither(sd.getMobilePhoneNumber(), nonSd.getMobilePhoneNumber(), eaa.getMobilePhoneNumber());
        assertEither(sd.getPseudonym(), nonSd.getPseudonym(), eaa.getPseudonym());

        assertEither(sd.getPersonalAdministrativeNumber(), nonSd.getPersonalAdministrativeNumber(), eaa.getPersonalAdministrativeNumber());

        if (sd.getSex() != null || nonSd.getSex() != null) {
            assertEither(sd.getSex(), nonSd.getSex(), eaa.getGender());
        } else {
            assertEither(sd.getGender(), nonSd.getGender(), eaa.getGender());
        }

        assertEither(sd.getIssuingCountry(), nonSd.getIssuingCountry(), eaa.getDocumentIssuingAuthorityCountry());
        assertEither(sd.getIssuingAuthority(), nonSd.getIssuingAuthority(), eaa.getDocumentIssuingAuthority());
        assertEither(sd.getIssuingJurisdiction(), nonSd.getIssuingJurisdiction(), eaa.getDocumentIssuingAuthorityJurisdiction());
        assertEither(sd.getDocumentNumber(), nonSd.getDocumentNumber(), eaa.getDocumentNumber());

        assertEither(sd.getAgeInYears(), nonSd.getAgeInYears(), eaa.getAgeInYears());
        assertEither(sd.getAgeBirthYear(), nonSd.getAgeBirthYear(), eaa.getAgeBirthYear());
        assertEither(sd.getTrustAnchor(), nonSd.getTrustAnchor(), eaa.getTrustAnchor());

        if (Utils.isMapNotEmpty(sd.getAgeOverNN()) || Utils.isMapNotEmpty(nonSd.getAgeOverNN())) {
            Set<Integer> ages = new HashSet<>();

            if (Utils.isMapNotEmpty(sd.getAgeOverNN())) {
                ages.addAll(sd.getAgeOverNN().keySet());
            }

            if (Utils.isMapNotEmpty(nonSd.getAgeOverNN())) {
                ages.addAll(nonSd.getAgeOverNN().keySet());
            }

            for (Integer age : ages) {
                Boolean sdValue = Utils.isMapNotEmpty(sd.getAgeOverNN()) ? sd.getAgeOverNN().get(age) : null;
                Boolean nonSdValue = Utils.isMapNotEmpty(nonSd.getAgeOverNN()) ? nonSd.getAgeOverNN().get(age) : null;

                assertEither(sdValue, nonSdValue, eaa.isAgeOver(age));
            }
        }

        assertEither(sd.getIssuingAuthorityRegistrationIdentifier(), nonSd.getIssuingAuthorityRegistrationIdentifier(), eaa.getIssuingRegistrationIdentifier());

        if (sd.getDateOfIssuance() != null || nonSd.getDateOfIssuance() != null) {
            assertEitherDate(sd.getDateOfIssuance(), nonSd.getDateOfIssuance(), eaa.getAdministrativeIssuanceDate());
        } else {
            assertEitherDate(sd.getAdministrativeIssuanceDate(), nonSd.getAdministrativeIssuanceDate(), eaa.getAdministrativeIssuanceDate());
        }
        if (sd.getDateOfExpiry() != null || nonSd.getDateOfExpiry() != null) {
            assertEitherDate(sd.getDateOfExpiry(), nonSd.getDateOfExpiry(), eaa.getAdministrativeExpirationDate());
        } else {
            assertEitherDate(sd.getAdministrativeExpirationDate(), nonSd.getAdministrativeExpirationDate(), eaa.getAdministrativeExpirationDate());
        }

        assertEither(sd.getPicture(), nonSd.getPicture(), eaa.getPictureUrl());
        assertEither(sd.getNickname(), nonSd.getNickname(), eaa.getNickname());

        assertEither(sd.getPreferredNickname(), nonSd.getPreferredNickname(), eaa.getShortName());

        assertEither(sd.getName(), nonSd.getName(), eaa.getFullName());
        assertEither(sd.getMiddleName(), nonSd.getMiddleName(), eaa.getMiddleName());
        assertEither(sd.getProfile(), nonSd.getProfile(), eaa.getProfileUrl());
        assertEither(sd.getWebsite(), nonSd.getWebsite(), eaa.getWebsiteUrl());

        assertEither(sd.getEmailVerified(), nonSd.getEmailVerified(), eaa.getEmailVerified());

        assertEither(sd.getZoneinfo(), nonSd.getZoneinfo(), eaa.getTimezone());
        assertEither(sd.getLocale(), nonSd.getLocale(), eaa.getLocale());
        assertEither(sd.getPhoneNumberVerified(), nonSd.getPhoneNumberVerified(), eaa.getPhoneNumberVerified());

        assertEitherDate(sd.getUpdatedAt(), nonSd.getUpdatedAt(), eaa.getEAAUpdatedAt());

        assertEither(sd.getBirthMiddleName(), nonSd.getBirthMiddleName(), eaa.getBirthMiddleName());
        assertEither(sd.getSalutation(), nonSd.getSalutation(), eaa.getSalutation());

        assertEither(sd.getAttestedAttributesSubjectIdentifier(), nonSd.getAttestedAttributesSubjectIdentifier(), eaa.getAttestedAttributesSubjectId());
        assertEither(sd.getAttestedAttributesSubjectPseudonym(), nonSd.getAttestedAttributesSubjectPseudonym(), eaa.getAttestedAttributesSubjectPseudonym());

        List<ClaimWrapper> selectivelyDisclosableClaims = eaa.getSelectivelyDisclosableClaims();
        if (parametersContainSelectivelyDisclosablClaims()) {
            assertFalse(selectivelyDisclosableClaims.isEmpty());
        } else {
            assertTrue(selectivelyDisclosableClaims.isEmpty());
        }
    }

    private <T> void assertEither(T sdValue, T nonSdValue, T actual) {
        if (sdValue == null && nonSdValue == null) {
            assertNull(actual);
        } else {
            assertTrue(Objects.equals(sdValue, actual) ||  Objects.equals(nonSdValue, actual),
                    String.format("Expected [%s] or [%s] but got [%s]", sdValue, nonSdValue, actual));
        }
    }

    private void assertEitherDate(Date sdValue, Date nonSdValue, Date actual) {
        if (actual == null && sdValue == null) {
            assertNull(actual);

        } else {
            String actualValue = DSSUtils.formatDateToRFC(actual);
            String sdFormatted = DSSUtils.formatDateToRFC(sdValue);
            String nonSdFormatted = DSSUtils.formatDateToRFC(nonSdValue);

            assertTrue(Objects.equals(sdFormatted, actualValue) || Objects.equals(nonSdFormatted, actualValue),
                    String.format("Expected [%s] or [%s] but got [%s]", sdFormatted, nonSdFormatted, actualValue));
        }
    }

    private boolean parametersContainSelectivelyDisclosablClaims() {
        if (hasConfiguredClaims(getPayloadParameters().selectivelyDisclosable())) {
            return true;
        }

        return hasSDClaims(getPayloadParameters().selectivelyDisclosable()) || hasSDClaims(getPayloadParameters().nonSelectivelyDisclosable());
    }

    private boolean hasConfiguredClaims(SDJWTClaimParameters p) {
        return p.getIssuanceDate() != null
                || p.getSubject() != null

                || p.getGivenName() != null
                || p.getFamilyName() != null
                || p.getBirthdate() != null
                || (p.getNationalities() != null && !p.getNationalities().isEmpty())
                || p.getEmail() != null
                || p.getPhoneNumber() != null

                || p.getPostalAddress() != null
                || p.getAddressHouseNumber() != null
                || p.getAddressStreet() != null
                || p.getAddressCity() != null
                || p.getAddressState() != null
                || p.getAddressPostalCode() != null
                || p.getAddressCountry() != null

                || p.getPlaceOfBirthCountry() != null
                || p.getPlaceOfBirthRegion() != null
                || p.getPlaceOfBirthLocality() != null
                || p.getBirthGivenName() != null
                || p.getBirthFamilyName() != null
                || p.getTitle() != null
                || p.getMobilePhoneNumber() != null
                || p.getPseudonym() != null

                || p.getPersonalAdministrativeNumber() != null
                || p.getSex() != null
                || p.getIssuingCountry() != null
                || p.getIssuingAuthority() != null
                || p.getIssuingJurisdiction() != null
                || p.getDocumentNumber() != null
                || p.getAgeInYears() != null
                || p.getAgeBirthYear() != null
                || p.getTrustAnchor() != null
                || (p.getAgeOverNN() != null && !p.getAgeOverNN().isEmpty())

                || p.getIssuingAuthorityRegistrationIdentifier() != null
                || p.getAdministrativeIssuanceDate() != null
                || p.getAdministrativeExpirationDate() != null

                || p.getPicture() != null
                || p.getNickname() != null
                || p.getPreferredNickname() != null
                || p.getName() != null
                || p.getMiddleName() != null
                || p.getProfile() != null
                || p.getWebsite() != null
                || p.getEmailVerified() != null
                || p.getGender() != null
                || p.getZoneinfo() != null
                || p.getLocale() != null
                || p.getPhoneNumberVerified() != null
                || p.getUpdatedAt() != null

                || p.getBirthMiddleName() != null
                || p.getSalutation() != null

                || p.getDateOfExpiry() != null
                || p.getDateOfIssuance() != null

                || p.getAttestedAttributesSubjectIdentifier() != null
                || p.getAttestedAttributesSubjectPseudonym() != null
                || (p.getAttestedAttributes() != null && !p.getAttestedAttributes().isEmpty())

                || !p.getOtherClaims().isEmpty();
    }

    private boolean hasSDClaims(SDJWTClaimParameters claimParameters) {
        return claimParameters.getOtherClaims().stream().anyMatch(this::hasSDClaims);
    }

    private boolean hasSDClaims(SDJWTEAAClaim claim) {
        if (claim == null) {
            return false;
        }

        if (claim.isSelectivelyDisclosable()) {
            return true;
        }

        if (claim instanceof SDJWTEAAClaimObject) {
            SDJWTEAAClaimObject object = (SDJWTEAAClaimObject) claim;

            return object.getChildren() != null
                    && object.getChildren().stream().anyMatch(this::hasSDClaims);

        } else if (claim instanceof SDJWTEAAClaimArray) {
            SDJWTEAAClaimArray array = (SDJWTEAAClaimArray) claim;

            return array.getElements() != null
                    && array.getElements().stream().anyMatch(this::hasSDClaims);

        } else {
            return false;
        }
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            JAdESSignatureParameters signatureParameters = signatureWrapper.isKeyBindingSignature() ? getKeyBindingSignatureParameters() : getSignatureParameters();
            FoundCertificatesProxy foundCertificates = signatureWrapper.foundCertificates();
            List<RelatedCertificateWrapper> signingCertificates = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
            assertEquals(1, signingCertificates.size());

            List<CertificateRefWrapper> references = signingCertificates.get(0).getReferences();
            List<RelatedCertificateWrapper> kidCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER);
            List<RelatedCertificateWrapper> x5uCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL);

            int signCertRefs = 1 + (Utils.isCollectionNotEmpty(kidCerts) ? 1 : 0) + (Utils.isCollectionNotEmpty(x5uCerts) ? 1 : 0);
            assertEquals(signCertRefs, references.size());

            if (signatureParameters.isIncludeKeyIdentifier()) {
                assertEquals(1, kidCerts.size());
            } else if (Utils.isStringNotEmpty(signatureParameters.getX509Url())) {
                assertTrue(Utils.isCollectionNotEmpty(x5uCerts));
            } else {
                assertEquals(0, kidCerts.size());
                assertEquals(0, x5uCerts.size());
            }

            for (CertificateRefWrapper certificateRef : references) {
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
    protected void checkContentType(DiagnosticData diagnosticData) {
        super.checkContentType(diagnosticData);

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            // The cty header parameter should not be present if the content type is implied by the JWS Payload.
            assertNull(signatureWrapper.getContentType());
        }
    }

}

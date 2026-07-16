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
package eu.europa.esig.dss.ws.eaa.creation.common.builder;

import eu.europa.esig.dss.eaa.common.creation.AbstractEAAClaimParameters;
import eu.europa.esig.dss.eaa.common.creation.AbstractEAAPayloadParameters;
import eu.europa.esig.dss.eaa.common.creation.EAAPayloadParameters;
import eu.europa.esig.dss.eaa.common.creation.EAAStatusList;
import eu.europa.esig.dss.eaa.sd.jwt.creation.ETSIEAAStatusList;
import eu.europa.esig.dss.eaa.sd.jwt.creation.SDJWTClaimParameters;
import eu.europa.esig.dss.eaa.sd.jwt.creation.SDJWTEAAPayloadParameters;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaimParameters;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAPayloadParameters;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocIdentifierList;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.security.DSSPublicKeySecurityFactory;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteCertificateConverter;
import eu.europa.esig.dss.ws.eaa.creation.common.converter.MdocEAAClaimFromDTOConverter;
import eu.europa.esig.dss.ws.eaa.creation.common.converter.SDJWTEAAClaimFromDTOConverter;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.AgeOverNNDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.BiometricTemplateNNDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DrivingPrivilegeCodeDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DrivingPrivilegeDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.RemoteEAAClaimParameters;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.RemoteEAAPayloadParameters;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds {@code EAAPayloadParameters} from {@link RemoteEAAPayloadParameters}
 *
 */
public class RemoteEAAPayloadParametersBuilder {

    /** DTO representing the signature parameters */
    private final RemoteEAAPayloadParameters remoteEAAPayloadParameters;

    /**
     * Default constructor
     *
     * @param remoteEAAPayloadParameters {@link RemoteEAAPayloadParameters}
     */
    public RemoteEAAPayloadParametersBuilder(final RemoteEAAPayloadParameters remoteEAAPayloadParameters) {
        Objects.requireNonNull(remoteEAAPayloadParameters, "RemoteEAAPayloadParameters must be defined!");
        Objects.requireNonNull(remoteEAAPayloadParameters.getEaaType(), "EAA type must be definedy!");
        this.remoteEAAPayloadParameters = remoteEAAPayloadParameters;
    }

    /**
     * Builds the {@code SerializableSignatureParameters}
     *
     * @return {@link SerializableSignatureParameters}
     */
    public EAAPayloadParameters build() {
        AbstractEAAPayloadParameters eaaPayloadParameters;
        switch (remoteEAAPayloadParameters.getEaaType()) {
            case SD_JWT_VC:
                eaaPayloadParameters = buildSDJWTVCParameters(remoteEAAPayloadParameters);
                break;
            case ISO_IEC_MDOC:
                eaaPayloadParameters = buildMdocParameters(remoteEAAPayloadParameters);
                break;
            default:
                throw new UnsupportedOperationException(String.format("Unsupported EAA format: '%s'. " +
                        "SD-JWT VC and ISO/IEC mdoc are only supported.", remoteEAAPayloadParameters.getEaaType()));
        }
        return eaaPayloadParameters;
    }

    /**
     * Builds a payload parameters instance for SD-JWT VC EAA type
     *
     * @param remoteEAAPayloadParameters {@link RemoteEAAPayloadParameters}
     * @return {@link SDJWTEAAPayloadParameters}
     */
    protected SDJWTEAAPayloadParameters buildSDJWTVCParameters(RemoteEAAPayloadParameters remoteEAAPayloadParameters) {
        final SDJWTEAAPayloadParameters payloadParameters = new SDJWTEAAPayloadParameters();
        if (remoteEAAPayloadParameters.getIssuer() != null) {
            payloadParameters.setIssuer(remoteEAAPayloadParameters.getIssuer());
        }
        if (remoteEAAPayloadParameters.getSubject() != null) {
            payloadParameters.setSubject(remoteEAAPayloadParameters.getSubject());
        }
        if (remoteEAAPayloadParameters.getVerifiableCredentialsType() != null) {
            payloadParameters.setVerifiableCredentialsType(remoteEAAPayloadParameters.getVerifiableCredentialsType());
        }
        if (remoteEAAPayloadParameters.getVerifiableCredentialsTypeIntegrity() != null) {
            payloadParameters.setVerifiableCredentialsTypeIntegrity(
                    DTOConverter.toDigest(remoteEAAPayloadParameters.getVerifiableCredentialsTypeIntegrity()));
        }
        fillCommonParameters(payloadParameters, remoteEAAPayloadParameters);
        fillSDJWTClaimsParameters(payloadParameters.nonSelectivelyDisclosable(), remoteEAAPayloadParameters.getNonSelectivelyDisclosable());
        fillSDJWTClaimsParameters(payloadParameters.selectivelyDisclosable(), remoteEAAPayloadParameters.getSelectivelyDisclosable());
        return payloadParameters;
    }

    /**
     * Builds a payload parameters instance for Mdoc type
     *
     * @param remoteEAAPayloadParameters {@link RemoteEAAPayloadParameters}
     * @return {@link MdocEAAPayloadParameters}
     */
    protected MdocEAAPayloadParameters buildMdocParameters(RemoteEAAPayloadParameters remoteEAAPayloadParameters) {
        final MdocEAAPayloadParameters payloadParameters = new MdocEAAPayloadParameters();
        if (remoteEAAPayloadParameters.getDocType() != null) {
            payloadParameters.setDocType(remoteEAAPayloadParameters.getDocType());
        }
        if (remoteEAAPayloadParameters.getSigned() != null) {
            payloadParameters.setSigned(remoteEAAPayloadParameters.getSigned());
        }
        if (remoteEAAPayloadParameters.getValidFrom() != null) {
            payloadParameters.setValidFrom(remoteEAAPayloadParameters.getValidFrom());
        }
        if (remoteEAAPayloadParameters.getValidUntil() != null) {
            payloadParameters.setValidUntil(remoteEAAPayloadParameters.getValidUntil());
        }
        if (remoteEAAPayloadParameters.getExpectedUpdate() != null) {
            payloadParameters.setExpectedUpdate(remoteEAAPayloadParameters.getExpectedUpdate());
        }
        if (remoteEAAPayloadParameters.getIdentifierList() != null) {
            CertificateToken certificate = RemoteCertificateConverter.toCertificateToken(
                    remoteEAAPayloadParameters.getIdentifierList().getCertificate());
            MdocIdentifierList identifierList = new MdocIdentifierList(
                    remoteEAAPayloadParameters.getIdentifierList().getIdentifier(),
                    remoteEAAPayloadParameters.getIdentifierList().getUri(),
                    certificate);
            payloadParameters.setIdentifierList(identifierList);
        }
        fillCommonParameters(payloadParameters, remoteEAAPayloadParameters);
        fillMdocClaimsParameters(payloadParameters.selectivelyDisclosable(), remoteEAAPayloadParameters.getSelectivelyDisclosable());
        return payloadParameters;
    }

    /**
     * Fills the common configuration of the {@code payloadParameters} from the {@code remoteEAAPayloadParameters} definition
     *
     * @param payloadParameters {@link AbstractEAAPayloadParameters}
     * @param remoteEAAPayloadParameters {@link RemoteEAAPayloadParameters}
     */
    protected void fillCommonParameters(AbstractEAAPayloadParameters payloadParameters, RemoteEAAPayloadParameters remoteEAAPayloadParameters) {
        if (remoteEAAPayloadParameters.getDigestAlgorithm() != null) {
            payloadParameters.setDigestAlgorithm(remoteEAAPayloadParameters.getDigestAlgorithm());
        }
        if (remoteEAAPayloadParameters.getIssuanceDate() != null) {
            payloadParameters.setIssuanceDate(remoteEAAPayloadParameters.getIssuanceDate());
        }
        if (remoteEAAPayloadParameters.getNotBeforeDate() != null) {
            payloadParameters.setNotBeforeDate(remoteEAAPayloadParameters.getNotBeforeDate());
        }
        if (remoteEAAPayloadParameters.getExpirationDate() != null) {
            payloadParameters.setExpirationDate(remoteEAAPayloadParameters.getExpirationDate());
        }
        if (remoteEAAPayloadParameters.getDeviceKey() != null) {
            if (remoteEAAPayloadParameters.getDeviceKey().getPublicKey() != null) {
                PublicKey publicKey = DSSPublicKeySecurityFactory.BINARY_INSTANCE.build(remoteEAAPayloadParameters.getDeviceKey().getPublicKey());
                payloadParameters.setDeviceKey(publicKey);
            } else if (remoteEAAPayloadParameters.getDeviceKey().getCertificate() != null) {
                CertificateToken certificateToken = RemoteCertificateConverter.toCertificateToken(
                        remoteEAAPayloadParameters.getDeviceKey().getCertificate());
                payloadParameters.setDeviceKey(certificateToken);
            }
        }
        if (remoteEAAPayloadParameters.getStatusList() != null) {
            EAAStatusList eaaStatusList;
            if (remoteEAAPayloadParameters.getStatusList().getType() != null ||
                    remoteEAAPayloadParameters.getStatusList().getPurpose() != null) {
                eaaStatusList = new ETSIEAAStatusList(
                        remoteEAAPayloadParameters.getStatusList().getType(),
                        remoteEAAPayloadParameters.getStatusList().getPurpose(),
                        remoteEAAPayloadParameters.getStatusList().getIndex(),
                        remoteEAAPayloadParameters.getStatusList().getUri());
            } else {
                CertificateToken certificate = RemoteCertificateConverter.toCertificateToken(
                        remoteEAAPayloadParameters.getStatusList().getCertificate());
                eaaStatusList = new EAAStatusList(remoteEAAPayloadParameters.getStatusList().getIndex(),
                        remoteEAAPayloadParameters.getStatusList().getUri(), certificate);
            }
            payloadParameters.setStatusList(eaaStatusList);
        }
        if (remoteEAAPayloadParameters.getCategory() != null) {
            payloadParameters.setCategory(remoteEAAPayloadParameters.getCategory());
        }
        if (remoteEAAPayloadParameters.getShortLived() != null) {
            payloadParameters.setShortLived(remoteEAAPayloadParameters.getShortLived());
        }
        if (remoteEAAPayloadParameters.getOneTime() != null) {
            payloadParameters.setOneTime(remoteEAAPayloadParameters.getOneTime());
        }
        if (remoteEAAPayloadParameters.getDecoyDigestNumber() != null) {
            payloadParameters.setDecoyDigestNumber(remoteEAAPayloadParameters.getDecoyDigestNumber());
        }
        if (remoteEAAPayloadParameters.getShuffleHashes() != null) {
            payloadParameters.setShuffleHashes(remoteEAAPayloadParameters.getShuffleHashes());
        }
    }

    /**
     * Fills {@code claimParameters} from the {@code selectivelyDisclosable} definition
     *
     * @param claimParameters {@link SDJWTClaimParameters}
     * @param selectivelyDisclosable {@link RemoteEAAClaimParameters}
     */
    protected void fillSDJWTClaimsParameters(SDJWTClaimParameters claimParameters, RemoteEAAClaimParameters selectivelyDisclosable) {
        if (selectivelyDisclosable == null) {
            return;
        }

        if (selectivelyDisclosable.getPicture() != null) {
            claimParameters.setPicture(selectivelyDisclosable.getPicture());
        }
        if (selectivelyDisclosable.getNickname() != null) {
            claimParameters.setNickname(selectivelyDisclosable.getNickname());
        }
        if (selectivelyDisclosable.getPreferredNickname() != null) {
            claimParameters.setPreferredNickname(selectivelyDisclosable.getPreferredNickname());
        }
        if (selectivelyDisclosable.getName() != null) {
            claimParameters.setName(selectivelyDisclosable.getName());
        }
        if (selectivelyDisclosable.getMiddleName() != null) {
            claimParameters.setMiddleName(selectivelyDisclosable.getMiddleName());
        }
        if (selectivelyDisclosable.getProfile() != null) {
            claimParameters.setProfile(selectivelyDisclosable.getProfile());
        }
        if (selectivelyDisclosable.getWebsite() != null) {
            claimParameters.setWebsite(selectivelyDisclosable.getWebsite());
        }
        if (selectivelyDisclosable.getEmailVerified() != null) {
            claimParameters.setEmailVerified(selectivelyDisclosable.getEmailVerified());
        }
        if (selectivelyDisclosable.getGender() != null) {
            claimParameters.setGender(selectivelyDisclosable.getGender());
        }
        if (selectivelyDisclosable.getZoneinfo() != null) {
            claimParameters.setZoneinfo(selectivelyDisclosable.getZoneinfo());
        }
        if (selectivelyDisclosable.getLocale() != null) {
            claimParameters.setLocale(selectivelyDisclosable.getLocale());
        }
        if (selectivelyDisclosable.getPhoneNumberVerified() != null) {
            claimParameters.setPhoneNumberVerified(selectivelyDisclosable.getPhoneNumberVerified());
        }
        if (selectivelyDisclosable.getUpdatedAt() != null) {
            claimParameters.setUpdatedAt(selectivelyDisclosable.getUpdatedAt());
        }
        if (selectivelyDisclosable.getBirthMiddleName() != null) {
            claimParameters.setBirthMiddleName(selectivelyDisclosable.getBirthMiddleName());
        }
        if (selectivelyDisclosable.getSalutation() != null) {
            claimParameters.setSalutation(selectivelyDisclosable.getSalutation());
        }
        if (selectivelyDisclosable.getDateOfExpiry() != null) {
            claimParameters.setDateOfExpiry(selectivelyDisclosable.getDateOfExpiry());
        }
        if (selectivelyDisclosable.getDateOfIssuance() != null) {
            claimParameters.setDateOfIssuance(selectivelyDisclosable.getDateOfIssuance());
        }
        if (selectivelyDisclosable.getAttestedAttributesSubjectIdentifier() != null) {
            claimParameters.setAttestedAttributesSubjectIdentifier(selectivelyDisclosable.getAttestedAttributesSubjectIdentifier(), selectivelyDisclosable.getAttestedAttributes());
        }
        if (selectivelyDisclosable.getAttestedAttributesSubjectPseudonym() != null) {
            claimParameters.setAttestedAttributesSubjectPseudonym(selectivelyDisclosable.getAttestedAttributesSubjectPseudonym(), selectivelyDisclosable.getAttestedAttributes());
        }

        if (selectivelyDisclosable.getOtherClaims() != null && !selectivelyDisclosable.getOtherClaims().isEmpty()) {
            final SDJWTEAAClaimFromDTOConverter converter = new SDJWTEAAClaimFromDTOConverter();
            selectivelyDisclosable.getOtherClaims().forEach(c -> claimParameters.addClaim(converter.apply(c)));
        }
        fillCommonClaims(claimParameters, selectivelyDisclosable);
    }

    /**
     * Fills {@code claimParameters} from the {@code selectivelyDisclosable} definition
     *
     * @param claimParameters {@link MdocEAAClaimParameters}
     * @param selectivelyDisclosable {@link RemoteEAAClaimParameters}
     */
    protected void fillMdocClaimsParameters(MdocEAAClaimParameters claimParameters, RemoteEAAClaimParameters selectivelyDisclosable) {
        if (selectivelyDisclosable == null) {
            return;
        }

        if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
            claimParameters.setBirthdateApproximateMask(selectivelyDisclosable.getBirthdateApproximateMask());
        }
        if (selectivelyDisclosable.getPlaceOfBirth() != null) {
            claimParameters.setPlaceOfBirth(selectivelyDisclosable.getPlaceOfBirth());
        }
        if (selectivelyDisclosable.getNationality() != null) {
            claimParameters.setNationality(selectivelyDisclosable.getNationality());
        }
        if (selectivelyDisclosable.getPortrait() != null) {
            claimParameters.setPortrait(selectivelyDisclosable.getPortrait());
        }
        if (selectivelyDisclosable.getDrivingPrivileges() != null && !selectivelyDisclosable.getDrivingPrivileges().isEmpty()) {
            List<MdocDrivingPrivilege> drivingPrivileges = new ArrayList<>();
            for (DrivingPrivilegeDTO dto : selectivelyDisclosable.getDrivingPrivileges()) {
                MdocDrivingPrivilege drivingPrivilege = new MdocDrivingPrivilege(dto.getVehicleCategoryCode());
                if (dto.getIssueDate() != null) {
                    drivingPrivilege.setIssueDate(dto.getIssueDate());
                }
                if (dto.getExpiryDate() != null) {
                    drivingPrivilege.setExpiryDate(dto.getExpiryDate());
                }
                if (dto.getCodes() != null && !dto.getCodes().isEmpty()) {
                    for (DrivingPrivilegeCodeDTO codeDTO : dto.getCodes()) {
                        drivingPrivilege.addCode(codeDTO.getCode(), codeDTO.getSign(), codeDTO.getValue());
                    }
                }
                drivingPrivileges.add(drivingPrivilege);
            }
            claimParameters.setDrivingPrivileges(drivingPrivileges);
        }
        if (selectivelyDisclosable.getDistinguishingSign() != null) {
            claimParameters.setDistinguishingSign(selectivelyDisclosable.getDistinguishingSign());
        }
        if (selectivelyDisclosable.getHeight() != null) {
            claimParameters.setHeight(selectivelyDisclosable.getHeight());
        }
        if (selectivelyDisclosable.getWeight() != null) {
            claimParameters.setWeight(selectivelyDisclosable.getWeight());
        }
        if (selectivelyDisclosable.getEyeColour() != null) {
            claimParameters.setEyeColour(selectivelyDisclosable.getEyeColour());
        }
        if (selectivelyDisclosable.getHairColour() != null) {
            claimParameters.setHairColour(selectivelyDisclosable.getHairColour());
        }
        if (selectivelyDisclosable.getPortraitCaptureDate() != null) {
            claimParameters.setPortraitCaptureDate(selectivelyDisclosable.getPortraitCaptureDate());
        }
        if (selectivelyDisclosable.getBiometricTemplate() != null && !selectivelyDisclosable.getBiometricTemplate().isEmpty()) {
            for (BiometricTemplateNNDTO biometricTemplateNNDTO : selectivelyDisclosable.getBiometricTemplate()) {
                claimParameters.setBiometricTemplate(biometricTemplateNNDTO.getType(), biometricTemplateNNDTO.getData());
            }
        }
        if (selectivelyDisclosable.getBiometricTemplateFace() != null) {
            claimParameters.setBiometricTemplateFace(selectivelyDisclosable.getBiometricTemplateFace());
        }
        if (selectivelyDisclosable.getSignatureUsualMark() != null) {
            claimParameters.setSignatureUsualMark(selectivelyDisclosable.getSignatureUsualMark());
        }
        if (selectivelyDisclosable.getFingerprint() != null) {
            claimParameters.setFingerprint(selectivelyDisclosable.getFingerprint());
        }
        if (selectivelyDisclosable.getBusinessName() != null) {
            claimParameters.setBusinessName(selectivelyDisclosable.getBusinessName());
        }
        if (selectivelyDisclosable.getOrganizationName() != null) {
            claimParameters.setOrganizationName(selectivelyDisclosable.getOrganizationName());
        }
        if (selectivelyDisclosable.getBirthFullName() != null) {
            claimParameters.setBirthFullName(selectivelyDisclosable.getBirthFullName());
        }
        if (selectivelyDisclosable.getProfession() != null) {
            claimParameters.setProfession(selectivelyDisclosable.getProfession());
        }
        if (selectivelyDisclosable.getRelationshipFather() != null) {
            claimParameters.setRelationshipFather(selectivelyDisclosable.getRelationshipFather());
        }
        if (selectivelyDisclosable.getRelationshipMother() != null) {
            claimParameters.setRelationshipMother(selectivelyDisclosable.getRelationshipMother());
        }
        if (selectivelyDisclosable.getRelationshipParent() != null) {
            claimParameters.setRelationshipParent(selectivelyDisclosable.getRelationshipParent());
        }
        if (selectivelyDisclosable.getRelationshipSon() != null) {
            claimParameters.setRelationshipSon(selectivelyDisclosable.getRelationshipSon());
        }
        if (selectivelyDisclosable.getRelationshipDaughter() != null) {
            claimParameters.setRelationshipDaughter(selectivelyDisclosable.getRelationshipDaughter());
        }
        if (selectivelyDisclosable.getRelationshipBrother() != null) {
            claimParameters.setRelationshipBrother(selectivelyDisclosable.getRelationshipBrother());
        }
        if (selectivelyDisclosable.getRelationshipSister() != null) {
            claimParameters.setRelationshipSister(selectivelyDisclosable.getRelationshipSister());
        }
        if (selectivelyDisclosable.getRelationshipSibling() != null) {
            claimParameters.setRelationshipSibling(selectivelyDisclosable.getRelationshipSibling());
        }
        if (selectivelyDisclosable.getRelationshipSpouse() != null) {
            claimParameters.setRelationshipSpouse(selectivelyDisclosable.getRelationshipSpouse());
        }
        if (selectivelyDisclosable.getRelationshipFatherInLaw() != null) {
            claimParameters.setRelationshipFatherInLaw(selectivelyDisclosable.getRelationshipFatherInLaw());
        }
        if (selectivelyDisclosable.getRelationshipMotherInLaw() != null) {
            claimParameters.setRelationshipMotherInLaw(selectivelyDisclosable.getRelationshipMotherInLaw());
        }
        if (selectivelyDisclosable.getRelationshipParentInLaw() != null) {
            claimParameters.setRelationshipParentInLaw(selectivelyDisclosable.getRelationshipParentInLaw());
        }
        if (selectivelyDisclosable.getRelationshipSonInLaw() != null) {
            claimParameters.setRelationshipSonInLaw(selectivelyDisclosable.getRelationshipSonInLaw());
        }
        if (selectivelyDisclosable.getRelationshipDaughterInLaw() != null) {
            claimParameters.setRelationshipDaughterInLaw(selectivelyDisclosable.getRelationshipDaughterInLaw());
        }
        if (selectivelyDisclosable.getRelationshipChildInLaw() != null) {
            claimParameters.setRelationshipChildInLaw(selectivelyDisclosable.getRelationshipChildInLaw());
        }
        if (selectivelyDisclosable.getRelationshipParentalAuthority() != null) {
            claimParameters.setRelationshipParentalAuthority(selectivelyDisclosable.getRelationshipParentalAuthority());
        }
        if (selectivelyDisclosable.getRelationshipLegalRepresentative() != null) {
            claimParameters.setRelationshipLegalRepresentative(selectivelyDisclosable.getRelationshipLegalRepresentative());
        }
        if (selectivelyDisclosable.getRelationshipAgent() != null) {
            claimParameters.setRelationshipAgent(selectivelyDisclosable.getRelationshipAgent());
        }
        if (selectivelyDisclosable.getDocumentType() != null) {
            claimParameters.setDocumentType(selectivelyDisclosable.getDocumentType());
        }
        if (selectivelyDisclosable.getAttestedAttributesSubjectFamilyName() != null ||
                selectivelyDisclosable.getAttestedAttributesSubjectGivenName() != null ||
                selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber() != null) {
            claimParameters.setAttestedAttributesSubject(
                    selectivelyDisclosable.getAttestedAttributesSubjectFamilyName(),
                    selectivelyDisclosable.getAttestedAttributesSubjectGivenName(),
                    selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber());
        }
        if (selectivelyDisclosable.getAttestedAttributesSubjectPseudonym() != null) {
            claimParameters.setAttestedAttributesSubjectPseudonym(selectivelyDisclosable.getAttestedAttributesSubjectPseudonym());
        }

        if (selectivelyDisclosable.getOtherClaims() != null && !selectivelyDisclosable.getOtherClaims().isEmpty()) {
            final MdocEAAClaimFromDTOConverter converter = new MdocEAAClaimFromDTOConverter();
            selectivelyDisclosable.getOtherClaims().forEach(c -> claimParameters.addClaim(converter.apply(c)));
        }
        fillCommonClaims(claimParameters, selectivelyDisclosable);
    }

    /**
     * Fills common claims from {@code remoteEAAPayloadParameters} to {@code claimParameters}
     *
     * @param claimParameters {@link AbstractEAAClaimParameters}
     * @param selectivelyDisclosable {@link RemoteEAAPayloadParameters}
     */
    protected void fillCommonClaims(AbstractEAAClaimParameters<?> claimParameters, RemoteEAAClaimParameters selectivelyDisclosable) {
        if (selectivelyDisclosable.getGivenName() != null) {
            claimParameters.setGivenName(selectivelyDisclosable.getGivenName());
        }
        if (selectivelyDisclosable.getFamilyName() != null) {
            claimParameters.setFamilyName(selectivelyDisclosable.getFamilyName());
        }
        if (selectivelyDisclosable.getBirthdate() != null) {
            claimParameters.setBirthdate(selectivelyDisclosable.getBirthdate());
        }
        if (selectivelyDisclosable.getNationalities() != null && !selectivelyDisclosable.getNationalities().isEmpty()) {
            claimParameters.setNationalities(selectivelyDisclosable.getNationalities());
        }
        if (selectivelyDisclosable.getEmail() != null) {
            claimParameters.setEmail(selectivelyDisclosable.getEmail());
        }
        if (selectivelyDisclosable.getPhoneNumber() != null) {
            claimParameters.setPhoneNumber(selectivelyDisclosable.getPhoneNumber());
        }
        if (selectivelyDisclosable.getPostalAddress() != null) {
            claimParameters.setPostalAddress(selectivelyDisclosable.getPostalAddress());
        }
        if (selectivelyDisclosable.getAddressHouseNumber() != null) {
            claimParameters.setAddressHouseNumber(selectivelyDisclosable.getAddressHouseNumber());
        }
        if (selectivelyDisclosable.getAddressStreet() != null) {
            claimParameters.setAddressStreet(selectivelyDisclosable.getAddressStreet());
        }
        if (selectivelyDisclosable.getAddressCity() != null) {
            claimParameters.setAddressCity(selectivelyDisclosable.getAddressCity());
        }
        if (selectivelyDisclosable.getAddressState() != null) {
            claimParameters.setAddressState(selectivelyDisclosable.getAddressState());
        }
        if (selectivelyDisclosable.getAddressPostalCode() != null) {
            claimParameters.setAddressPostalCode(selectivelyDisclosable.getAddressPostalCode());
        }
        if (selectivelyDisclosable.getAddressCountry() != null) {
            claimParameters.setAddressCountry(selectivelyDisclosable.getAddressCountry());
        }
        if (selectivelyDisclosable.getPlaceOfBirthCountry() != null) {
            claimParameters.setPlaceOfBirthCountry(selectivelyDisclosable.getPlaceOfBirthCountry());
        }
        if (selectivelyDisclosable.getPlaceOfBirthRegion() != null) {
            claimParameters.setPlaceOfBirthRegion(selectivelyDisclosable.getPlaceOfBirthRegion());
        }
        if (selectivelyDisclosable.getPlaceOfBirthLocality() != null) {
            claimParameters.setPlaceOfBirthLocality(selectivelyDisclosable.getPlaceOfBirthLocality());
        }
        if (selectivelyDisclosable.getBirthGivenName() != null) {
            claimParameters.setBirthGivenName(selectivelyDisclosable.getBirthGivenName());
        }
        if (selectivelyDisclosable.getBirthFamilyName() != null) {
            claimParameters.setBirthFamilyName(selectivelyDisclosable.getBirthFamilyName());
        }
        if (selectivelyDisclosable.getTitle() != null) {
            claimParameters.setTitle(selectivelyDisclosable.getTitle());
        }
        if (selectivelyDisclosable.getMobilePhoneNumber() != null) {
            claimParameters.setMobilePhoneNumber(selectivelyDisclosable.getMobilePhoneNumber());
        }
        if (selectivelyDisclosable.getPseudonym() != null) {
            claimParameters.setPseudonym(selectivelyDisclosable.getPseudonym());
        }
        if (selectivelyDisclosable.getPersonalAdministrativeNumber() != null) {
            claimParameters.setPersonalAdministrativeNumber(selectivelyDisclosable.getPersonalAdministrativeNumber());
        }
        if (selectivelyDisclosable.getSex() != null) {
            claimParameters.setSex(selectivelyDisclosable.getSex());
        }
        if (selectivelyDisclosable.getIssuingCountry() != null) {
            claimParameters.setIssuingCountry(selectivelyDisclosable.getIssuingCountry());
        }
        if (selectivelyDisclosable.getIssuingAuthority() != null) {
            claimParameters.setIssuingAuthority(selectivelyDisclosable.getIssuingAuthority());
        }
        if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
            claimParameters.setIssuingJurisdiction(selectivelyDisclosable.getIssuingJurisdiction());
        }
        if (selectivelyDisclosable.getDocumentNumber() != null) {
            claimParameters.setDocumentNumber(selectivelyDisclosable.getDocumentNumber());
        }
        if (selectivelyDisclosable.getAgeInYears() != null) {
            claimParameters.setAgeInYears(selectivelyDisclosable.getAgeInYears());
        }
        if (selectivelyDisclosable.getAgeBirthYear() != null) {
            claimParameters.setAgeBirthYear(selectivelyDisclosable.getAgeBirthYear());
        }
        if (selectivelyDisclosable.getTrustAnchor() != null) {
            claimParameters.setTrustAnchor(selectivelyDisclosable.getTrustAnchor());
        }
        if (selectivelyDisclosable.getAgeOverNN() != null && !selectivelyDisclosable.getAgeOverNN().isEmpty()) {
            for (AgeOverNNDTO ageOverNNDTO : selectivelyDisclosable.getAgeOverNN()) {
                claimParameters.setAgeOverNN(ageOverNNDTO.getAge(), ageOverNNDTO.getOver());
            }
        }
        if (selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier() != null) {
            claimParameters.setIssuingAuthorityRegistrationIdentifier(selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier());
        }
        if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
            claimParameters.setAdministrativeIssuanceDate(selectivelyDisclosable.getAdministrativeIssuanceDate());
        }
        if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
            claimParameters.setAdministrativeExpirationDate(selectivelyDisclosable.getAdministrativeExpirationDate());
        }
    }

}

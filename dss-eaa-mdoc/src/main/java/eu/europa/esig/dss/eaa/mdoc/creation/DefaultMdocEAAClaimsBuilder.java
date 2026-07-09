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

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.eaa.mdoc.ETSI194721Headers;
import eu.europa.esig.dss.eaa.mdoc.EUDIPIDHeaders;
import eu.europa.esig.dss.eaa.mdoc.ISO180135Headers;
import eu.europa.esig.dss.eaa.mdoc.ISO232202Headers;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * This class is used to provide a proper MdocEAAClaim implementation based on the document type.
 * The class defines default values for some properties, which may not be present on a specific implementation.
 *
 */
public abstract class DefaultMdocEAAClaimsBuilder implements MdocEAAClaimsBuilder {

    /**
     * Default constructor
     */
    protected DefaultMdocEAAClaimsBuilder() {
        // empty
    }

    /**
     * Creates claims for the payload parameters
     *
     * @param payloadParameters {@link MdocEAAPayloadParameters}
     * @return a list of {@link MdocEAAClaim}s
     */
    public List<MdocEAAClaim> buildClaims(MdocEAAPayloadParameters payloadParameters) {
        final List<MdocEAAClaim> result = new ArrayList<>();

        /* ETSI technical claims */
        addClaim(result, getIssuanceDate(payloadParameters));
        addClaim(result, getOneTime(payloadParameters));
        addClaim(result, getShortLived(payloadParameters));
        addClaim(result, getCategory(payloadParameters));

        /* Other selectively disclosable claims */

        MdocEAAClaimParameters selectivelyDisclosable = payloadParameters.selectivelyDisclosable();
        addClaim(result, getGivenName(selectivelyDisclosable));
        addClaim(result, getFamilyName(selectivelyDisclosable));
        addClaim(result, getEmail(selectivelyDisclosable));
        addClaim(result, getSex(selectivelyDisclosable));
        addClaim(result, getBirthdate(selectivelyDisclosable));
        addClaim(result, getPhoneNumber(selectivelyDisclosable));
        addClaim(result, getPlaceOfBirth(selectivelyDisclosable));
        addClaim(result, getNationality(selectivelyDisclosable));
        addClaim(result, getNationalities(selectivelyDisclosable));
        addClaim(result, getBirthGivenName(selectivelyDisclosable));
        addClaim(result, getBirthFamilyName(selectivelyDisclosable));
        addClaim(result, getTitle(selectivelyDisclosable));
        addClaim(result, getMobilePhoneNumber(selectivelyDisclosable));
        addClaim(result, getPseudonym(selectivelyDisclosable));
        addClaim(result, getIssuingCountry(selectivelyDisclosable));
        addClaim(result, getIssuingAuthority(selectivelyDisclosable));
        addClaim(result, getDocumentNumber(selectivelyDisclosable));
        addClaim(result, getPortrait(selectivelyDisclosable));
        addClaim(result, getDrivingPrivileges(selectivelyDisclosable));
        addClaim(result, getDistinguishingSign(selectivelyDisclosable));
        addClaim(result, getPersonalAdministrativeNumber(selectivelyDisclosable));
        addClaim(result, getHeight(selectivelyDisclosable));
        addClaim(result, getWeight(selectivelyDisclosable));
        addClaim(result, getEyeColour(selectivelyDisclosable));
        addClaim(result, getHairColour(selectivelyDisclosable));
        addClaim(result, getPostalAddress(selectivelyDisclosable));
        addClaim(result, getPortraitCaptureDate(selectivelyDisclosable));
        addClaim(result, getAgeInYears(selectivelyDisclosable));
        addClaim(result, getAgeBirthYear(selectivelyDisclosable));
        addClaims(result, getAgeOverNN(selectivelyDisclosable));
        addClaim(result, getIssuingJurisdiction(selectivelyDisclosable));
        addClaim(result, getResidentAddressCity(selectivelyDisclosable));
        addClaim(result, getResidentAddressState(selectivelyDisclosable));
        addClaim(result, getResidentAddressPostalCode(selectivelyDisclosable));
        addClaim(result, getResidentAddressCountry(selectivelyDisclosable));
        addClaims(result, getBiometricTemplate(selectivelyDisclosable));
        addClaim(result, getBiometricTemplateFace(selectivelyDisclosable));
        addClaim(result, getSignatureUsualMark(selectivelyDisclosable));
        addClaim(result, getFingerprint(selectivelyDisclosable));
        addClaim(result, getBusinessName(selectivelyDisclosable));
        addClaim(result, getOrganizationName(selectivelyDisclosable));
        addClaim(result, getBirthFullName(selectivelyDisclosable));
        addClaim(result, getProfession(selectivelyDisclosable));
        addClaim(result, getRelationshipFather(selectivelyDisclosable));
        addClaim(result, getRelationshipMother(selectivelyDisclosable));
        addClaim(result, getRelationshipParent(selectivelyDisclosable));
        addClaim(result, getRelationshipSon(selectivelyDisclosable));
        addClaim(result, getRelationshipDaughter(selectivelyDisclosable));
        addClaim(result, getRelationshipBrother(selectivelyDisclosable));
        addClaim(result, getRelationshipSister(selectivelyDisclosable));
        addClaim(result, getRelationshipSibling(selectivelyDisclosable));
        addClaim(result, getRelationshipSpouse(selectivelyDisclosable));
        addClaim(result, getRelationshipFatherInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipMotherInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipParentInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipSonInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipDaughterInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipChildInLaw(selectivelyDisclosable));
        addClaim(result, getRelationshipParentalAuthority(selectivelyDisclosable));
        addClaim(result, getRelationshipLegalRepresentative(selectivelyDisclosable));
        addClaim(result, getRelationshipAgent(selectivelyDisclosable));
        addClaim(result, getDocumentType(selectivelyDisclosable));
        addClaim(result, getAdministrativeIssuanceDate(selectivelyDisclosable));
        addClaim(result, getAdministrativeExpirationDate(selectivelyDisclosable));
        addClaim(result, getResidentAddressStreet(selectivelyDisclosable));
        addClaim(result, getResidentAddressHouseNumber(selectivelyDisclosable));
        addClaim(result, getTrustAnchor(selectivelyDisclosable));
        addClaim(result, getIssuingAuthorityRegistrationIdentifier(selectivelyDisclosable));
        addClaim(result, getAttestedAttributesSubject(selectivelyDisclosable));

        result.addAll(selectivelyDisclosable.getOtherClaims());

        return result;
    }

    /**
     * Gets mdoc claim generated for the issuanceDate parameter
     *
     * @param payloadParameters {@link MdocEAAPayloadParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getIssuanceDate(MdocEAAPayloadParameters payloadParameters) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getIssuanceDate(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the shortLived parameter
     *
     * @param payloadParameters {@link MdocEAAPayloadParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getShortLived(MdocEAAPayloadParameters payloadParameters) {
        return ETSI194721EAAClaimsBuilder.getInstance().getShortLived(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the oneTime parameter
     *
     * @param payloadParameters {@link MdocEAAPayloadParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getOneTime(MdocEAAPayloadParameters payloadParameters) {
        return ETSI194721EAAClaimsBuilder.getInstance().getOneTime(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the category parameter
     *
     * @param payloadParameters {@link MdocEAAPayloadParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getCategory(MdocEAAPayloadParameters payloadParameters) {
        return ETSI194721EAAClaimsBuilder.getInstance().getCategory(payloadParameters);
    }

    /**
     * Gets mdoc claim generated for the first name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getGivenName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the last name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getFamilyName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the email parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getEmail(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getEmail(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the gender parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getSex(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getSex(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birthdate parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBirthdate(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getBirthdate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the phone number parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPhoneNumber(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getPhoneNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the place of birth parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPlaceOfBirth(MdocEAAClaimParameters selectivelyDisclosable) {
        if (selectivelyDisclosable.getPlaceOfBirth() != null) {
            return ISO232201MIDEAAClaimsBuilder.getInstance().getPlaceOfBirth(selectivelyDisclosable);
        }
        if (selectivelyDisclosable.getPlaceOfBirthCountry() != null ||
                selectivelyDisclosable.getPlaceOfBirthLocality() != null ||
                selectivelyDisclosable.getPlaceOfBirthRegion() != null) {
            return EUDIPIDEAAClaimsBuilder.getInstance().getPlaceOfBirth(selectivelyDisclosable);
        }
        return null;
    }

    /**
     * Gets mdoc claim generated for the nationality parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getNationality(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getNationality(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the nationalities parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getNationalities(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getNationalities(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth first name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBirthGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getBirthGivenName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth last name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBirthFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getBirthFamilyName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the title parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getTitle(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getTitle(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the mobile phone number parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getMobilePhoneNumber(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getMobilePhoneNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the pseudonym parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPseudonym(MdocEAAClaimParameters selectivelyDisclosable) {
        return ETSI194721EAAClaimsBuilder.getInstance().getPseudonym(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing country parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getIssuingCountry(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getIssuingCountry(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing authority parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getIssuingAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getIssuingAuthority(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the document number parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getDocumentNumber(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getDocumentNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the portrait parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPortrait(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getPortrait(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the driving privileges parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getDrivingPrivileges(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getDrivingPrivileges(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the UN distinguishing sign parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getDistinguishingSign(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getDistinguishingSign(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative number parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPersonalAdministrativeNumber(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getPersonalAdministrativeNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the height parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getHeight(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getHeight(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the weight parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getWeight(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getWeight(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the eye colour parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getEyeColour(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getEyeColour(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the hair colour parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getHairColour(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getHairColour(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident address parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPostalAddress(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getPostalAddress(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the portrait capture date parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getPortraitCaptureDate(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getPortraitCaptureDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the age in years parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getAgeInYears(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getAgeInYears(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the age birth year parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getAgeBirthYear(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getAgeBirthYear(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claims generated for the age over NN parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return a list of {@link MdocEAAClaim}s
     */
    protected List<MdocEAAClaim> getAgeOverNN(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getAgeOverNN(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing jurisdiction parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getIssuingJurisdiction(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getIssuingJurisdiction(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident city parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressCity(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getResidentAddressCity(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident state parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressState(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getResidentAddressState(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident postal code parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressPostalCode(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getResidentAddressPostalCode(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident country parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressCountry(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getResidentAddressCountry(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claims generated for the biometric template parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return a list of {@link MdocEAAClaim}s
     */
    protected List<MdocEAAClaim> getBiometricTemplate(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getBiometricTemplate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the biometric template face
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBiometricTemplateFace(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getBiometricTemplateFace(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the signature usual mark parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getSignatureUsualMark(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO180135MDLEAAClaimsBuilder.getInstance().getSignatureUsualMark(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the fingerprint parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getFingerprint(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getFingerprint(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the business name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBusinessName(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getBusinessName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the organization name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getOrganizationName(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getOrganizationName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the birth full name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getBirthFullName(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getBirthFullName(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the profession parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getProfession(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getProfession(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship father parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipFather(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipFather(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship mother parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipMother(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipMother(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parent parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipParent(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipParent(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship son parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipSon(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipSon(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship daughter parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipDaughter(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipDaughter(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship brother parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipBrother(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipBrother(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship sister parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipSister(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipSister(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship sibling parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipSibling(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipSibling(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship spouse parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipSpouse(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipSpouse(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship father in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipFatherInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipFatherInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship mother in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipMotherInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipMotherInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parent in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipParentInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipParentInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship son in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipSonInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipSonInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship daughter in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipDaughterInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipDaughterInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship child in law parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipChildInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipChildInLaw(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship parental authority parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipParentalAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipParentalAuthority(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship legal representative parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipLegalRepresentative(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipLegalRepresentative(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the relationship agent parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getRelationshipAgent(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getRelationshipAgent(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the document type parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getDocumentType(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getDocumentType(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative issuance date parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getAdministrativeIssuanceDate(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getAdministrativeIssuanceDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the administrative expiration date parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getAdministrativeExpirationDate(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getAdministrativeExpirationDate(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident street parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressStreet(MdocEAAClaimParameters selectivelyDisclosable) {
        return ISO232201MIDEAAClaimsBuilder.getInstance().getResidentAddressStreet(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the resident house number parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getResidentAddressHouseNumber(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getResidentAddressHouseNumber(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the trust anchor parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getTrustAnchor(MdocEAAClaimParameters selectivelyDisclosable) {
        return EUDIPIDEAAClaimsBuilder.getInstance().getTrustAnchor(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the issuing authority registration identifier parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getIssuingAuthorityRegistrationIdentifier(MdocEAAClaimParameters selectivelyDisclosable) {
        return ETSI194721EAAClaimsBuilder.getInstance().getIssuingAuthorityRegistrationIdentifier(selectivelyDisclosable);
    }

    /**
     * Gets mdoc claim generated for the attested attributes subject family name parameter
     *
     * @param selectivelyDisclosable {@link MdocEAAClaimParameters}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim getAttestedAttributesSubject(MdocEAAClaimParameters selectivelyDisclosable) {
        return ETSI194721EAAClaimsBuilder.getInstance().getAttestedAttributesSubject(selectivelyDisclosable);
    }

    /**
     * Gets the namespace for the given claims category
     *
     * @return {@link String}
     */
    protected abstract String getNamespace();

    /**
     * Creates a new MdocEAAClaim using the name, value and the applicable namespace
     *
     * @param name {@link String}
     * @param value {@link Object}
     * @return {@link MdocEAAClaim}
     */
    protected MdocEAAClaim create(String name, Object value) {
        return MdocEAAClaim.create(getNamespace(), name, value);
    }

    /**
     * Adds the {@code claim} to the {@code result} list if not null
     *
     * @param result a list of {@link MdocEAAClaim}s
     * @param claim {@link MdocEAAClaim} to be added
     */
    protected void addClaim(final List<MdocEAAClaim> result, MdocEAAClaim claim) {
        if (claim != null) {
            result.add(claim);
        }
    }

    /**
     * Adds the {@code claim} to the {@code result} list if not null
     *
     * @param result a list of {@link MdocEAAClaim}s
     * @param claims a list of {@link MdocEAAClaim}s to be added
     */
    protected void addClaims(final List<MdocEAAClaim> result, List<MdocEAAClaim> claims) {
        if (Utils.isCollectionNotEmpty(claims)) {
            claims.forEach(c -> addClaim(result, c));
        }
    }

    /**
     * Provides claim definitions for the document conformant to ISO/IEC 18013-5 MDL mdoc.
     */
    protected static final class ISO180135MDLEAAClaimsBuilder extends DefaultMdocEAAClaimsBuilder {

        /** Singleton */
        private static ISO180135MDLEAAClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ISO180135MDLEAAClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ISO180135MDLEAAClaimsBuilder}
         */
        public static ISO180135MDLEAAClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ISO180135MDLEAAClaimsBuilder();
            }
            return instance;
        }

        @Override
        protected String getNamespace() {
            return MdocConstants.ISO18013_5_NAMESPACE;
        }

        @Override
        protected MdocEAAClaim getIssuanceDate(MdocEAAPayloadParameters payloadParameters) {
            if (payloadParameters.getIssuanceDate() != null) {
                return create(ISO180135Headers.ISSUE_DATE, payloadParameters.getIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(ISO180135Headers.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(ISO180135Headers.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getSex(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(ISO180135Headers.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthdate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    return super.getBirthdate(selectivelyDisclosable);
                }
                return create(ISO180135Headers.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPlaceOfBirth(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirth() != null) {
                return create(ISO180135Headers.BIRTH_PLACE, selectivelyDisclosable.getPlaceOfBirth());
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocEAAClaim getNationality(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getNationality() != null) {
                return create(ISO180135Headers.NATIONALITY, selectivelyDisclosable.getNationality());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(ISO180135Headers.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(ISO180135Headers.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDocumentNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(ISO180135Headers.LICENCE_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPortrait(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(ISO180135Headers.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDrivingPrivileges(MdocEAAClaimParameters selectivelyDisclosable) {
            if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getDrivingPrivileges())) {
                final CBORArray drivingPrivileges = new CBORArray();
                for (MdocDrivingPrivilege mdocDrivingPrivilege : selectivelyDisclosable.getDrivingPrivileges()) {
                    CBORMap drivingPrivilege = new CBORMap();
                    drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE, mdocDrivingPrivilege.getVehicleCategoryCode());
                    if (mdocDrivingPrivilege.getIssueDate() != null) {
                        drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_ISSUE_DATE, CBORUtils.toFullDate(mdocDrivingPrivilege.getIssueDate()));
                    }
                    if (mdocDrivingPrivilege.getExpiryDate() != null) {
                        drivingPrivilege.put(ISO180135Headers.DRIVING_PRIVILEGES_EXPIRY_DATE, CBORUtils.toFullDate(mdocDrivingPrivilege.getExpiryDate()));
                    }
                    if (Utils.isCollectionNotEmpty(mdocDrivingPrivilege.getCodes())) {
                        CBORArray codes = new CBORArray();
                        for (MdocDrivingPrivilege.Code mdocCode : mdocDrivingPrivilege.getCodes()) {
                            CBORMap code = new CBORMap();
                            code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_CODE, mdocCode.getCode());
                            if (mdocCode.getSign() != null) {
                                code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_SIGN, mdocCode.getSign());
                            }
                            if (mdocCode.getValue() != null) {
                                code.put(ISO180135Headers.DRIVING_PRIVILEGES_CODE_VALUE, mdocCode.getValue());
                            }
                            codes.add(code);
                        }
                    }
                    drivingPrivileges.add(drivingPrivilege);
                }
                return create(ISO180135Headers.DRIVING_PRIVILEGES, drivingPrivileges);
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDistinguishingSign(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDistinguishingSign() != null) {
                return create(ISO180135Headers.UN_DISTINGUISHING_SIGN, selectivelyDisclosable.getDistinguishingSign());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPersonalAdministrativeNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPersonalAdministrativeNumber() != null) {
                return create(ISO180135Headers.ADMINISTRATIVE_NUMBER, selectivelyDisclosable.getPersonalAdministrativeNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getHeight(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHeight() != null) {
                return create(ISO180135Headers.HEIGHT, selectivelyDisclosable.getHeight());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getWeight(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getWeight() != null) {
                return create(ISO180135Headers.WEIGHT, selectivelyDisclosable.getWeight());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getEyeColour(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEyeColour() != null) {
                return create(ISO180135Headers.EYE_COLOUR, selectivelyDisclosable.getEyeColour());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getHairColour(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHairColour() != null) {
                return create(ISO180135Headers.HAIR_COLOUR, selectivelyDisclosable.getHairColour());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPostalAddress(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(ISO180135Headers.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPortraitCaptureDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortraitCaptureDate() != null) {
                return create(ISO180135Headers.PORTRAIT_CAPTURE_DATE, selectivelyDisclosable.getPortraitCaptureDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAgeInYears(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeInYears() != null) {
                return create(ISO180135Headers.AGE_IN_YEARS, selectivelyDisclosable.getAgeInYears());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAgeBirthYear(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeBirthYear() != null) {
                return create(ISO180135Headers.AGE_BIRTH_YEAR, selectivelyDisclosable.getAgeBirthYear());
            }
            return null;
        }

        @Override
        protected List<MdocEAAClaim> getAgeOverNN(MdocEAAClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getAgeOverNN())) {
                final List<MdocEAAClaim> result = new ArrayList<>();
                for (Map.Entry<Integer, Boolean> entry : selectivelyDisclosable.getAgeOverNN().entrySet()) {
                    addClaim(result, create(ISO180135Headers.AGE_OVER_NN + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocEAAClaim getIssuingJurisdiction(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(ISO180135Headers.ISSUING_JURISDICTION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCity(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(ISO180135Headers.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressState(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(ISO180135Headers.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressPostalCode(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(ISO180135Headers.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(ISO180135Headers.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected List<MdocEAAClaim> getBiometricTemplate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getBiometricTemplate())) {
                final List<MdocEAAClaim> result = new ArrayList<>();
                for (Map.Entry<String, byte[]> entry : selectivelyDisclosable.getBiometricTemplate().entrySet()) {
                    addClaim(result, create(ISO180135Headers.BIOMETRIC_TEMPLATE_XX + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocEAAClaim getBiometricTemplateFace(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBiometricTemplateFace() != null) {
                return create(ISO180135Headers.BIOMETRIC_TEMPLATE_FACE, selectivelyDisclosable.getBiometricTemplateFace());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getSignatureUsualMark(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSignatureUsualMark() != null) {
                return create(ISO180135Headers.SIGNATURE, selectivelyDisclosable.getSignatureUsualMark());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeIssuanceDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(ISO180135Headers.ISSUE_DATE, selectivelyDisclosable.getAdministrativeIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeExpirationDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(ISO180135Headers.EXPIRY_DATE, selectivelyDisclosable.getAdministrativeExpirationDate());
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to ISO/IEC 23220-1 MID mdoc.
     */
    protected static final class ISO232201MIDEAAClaimsBuilder extends DefaultMdocEAAClaimsBuilder {

        /** Singleton */
        private static ISO232201MIDEAAClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ISO232201MIDEAAClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ISO232201MIDEAAClaimsBuilder}
         */
        public static ISO232201MIDEAAClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ISO232201MIDEAAClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.ISO23220_1_NAMESPACE;
        }

        @Override
        protected MdocEAAClaim getIssuanceDate(MdocEAAPayloadParameters payloadParameters) {
            if (payloadParameters.getIssuanceDate() != null) {
                return create(ISO232202Headers.ISSUE_DATE, payloadParameters.getIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(ISO232202Headers.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(ISO232202Headers.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getEmail(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEmail() != null) {
                return create(ISO232202Headers.EMAIL_ADDRESS, selectivelyDisclosable.getEmail());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getSex(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(ISO232202Headers.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthdate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                final CBORMap birthdate = new CBORMap();
                birthdate.put(ISO232202Headers.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    birthdate.put(ISO232202Headers.APPROXIMATE_MASK, selectivelyDisclosable.getBirthdateApproximateMask());
                }
                return create(ISO232202Headers.BIRTH_DATE, birthdate);
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPhoneNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPhoneNumber() != null) {
                return create(ISO232202Headers.TELEPHONE_NUMBER, selectivelyDisclosable.getPhoneNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPlaceOfBirth(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirth() != null) {
                return create(ISO232202Headers.BIRTHPLACE, selectivelyDisclosable.getPlaceOfBirth());
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocEAAClaim getNationality(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getNationality() != null) {
                return create(ISO232202Headers.NATIONALITY, selectivelyDisclosable.getNationality());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getTitle(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getTitle() != null) {
                return create(ISO232202Headers.TITLE, selectivelyDisclosable.getTitle());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(ISO232202Headers.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(ISO232202Headers.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDocumentNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(ISO232202Headers.DOCUMENT_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPortrait(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(ISO232202Headers.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getHeight(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getHeight() != null) {
                return create(ISO232202Headers.HEIGHT, selectivelyDisclosable.getHeight());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getWeight(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getWeight() != null) {
                return create(ISO232202Headers.WEIGHT, selectivelyDisclosable.getWeight());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPostalAddress(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(ISO232202Headers.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPortraitCaptureDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortraitCaptureDate() != null) {
                return create(ISO232202Headers.PORTRAIT_CAPTURE_DATE, selectivelyDisclosable.getPortraitCaptureDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAgeInYears(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeInYears() != null) {
                return create(ISO232202Headers.AGE_IN_YEARS, selectivelyDisclosable.getAgeInYears());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAgeBirthYear(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAgeBirthYear() != null) {
                return create(ISO232202Headers.AGE_BIRTH_YEAR, selectivelyDisclosable.getAgeBirthYear());
            }
            return null;
        }

        @Override
        protected List<MdocEAAClaim> getAgeOverNN(MdocEAAClaimParameters selectivelyDisclosable) {
            if (Utils.isMapNotEmpty(selectivelyDisclosable.getAgeOverNN())) {
                final List<MdocEAAClaim> result = new ArrayList<>();
                for (Map.Entry<Integer, Boolean> entry : selectivelyDisclosable.getAgeOverNN().entrySet()) {
                    addClaim(result, create(ISO232202Headers.AGE_OVER_NN + entry.getKey(), entry.getValue()));
                }
                return result;
            }
            return Collections.emptyList();
        }

        @Override
        protected MdocEAAClaim getIssuingJurisdiction(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(ISO232202Headers.ISSUING_SUBDIVISION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCity(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(ISO232202Headers.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressPostalCode(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(ISO232202Headers.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(ISO232202Headers.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressState(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(ISO232202Headers.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressStreet(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressStreet() != null) {
                return create(ISO232202Headers.RESIDENT_STREET, selectivelyDisclosable.getAddressStreet());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBiometricTemplateFace(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBiometricTemplateFace() != null) {
                return create(ISO232202Headers.BIOMETRIC_TEMPLATE_FACE, selectivelyDisclosable.getBiometricTemplateFace());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getFingerprint(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSignatureUsualMark() != null) {
                return create(ISO232202Headers.FINGERPRINT, selectivelyDisclosable.getFingerprint());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBusinessName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBusinessName() != null) {
                return create(ISO232202Headers.BUSINESS_NAME, selectivelyDisclosable.getBusinessName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getOrganizationName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getOrganizationName() != null) {
                return create(ISO232202Headers.ORGANIZATION_NAME, selectivelyDisclosable.getOrganizationName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthFullName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthFullName() != null) {
                return create(ISO232202Headers.NAME_AT_BIRTH, selectivelyDisclosable.getBirthFullName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getProfession(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getProfession() != null) {
                return create(ISO232202Headers.PROFESSION, selectivelyDisclosable.getProfession());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipFather(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipFather() != null) {
                return create(ISO232202Headers.RELATIONSHIP_FATHER, selectivelyDisclosable.getRelationshipFather());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipMother(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipMother() != null) {
                return create(ISO232202Headers.RELATIONSHIP_MOTHER, selectivelyDisclosable.getRelationshipMother());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipParent(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParent() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENT, selectivelyDisclosable.getRelationshipParent());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipSon(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSon() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SON, selectivelyDisclosable.getRelationshipSon());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipDaughter(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipDaughter() != null) {
                return create(ISO232202Headers.RELATIONSHIP_DAUGHTER, selectivelyDisclosable.getRelationshipDaughter());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipBrother(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipBrother() != null) {
                return create(ISO232202Headers.RELATIONSHIP_BROTHER, selectivelyDisclosable.getRelationshipBrother());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipSister(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSister() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SISTER, selectivelyDisclosable.getRelationshipSister());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipSibling(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSibling() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SIBLING, selectivelyDisclosable.getRelationshipSibling());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipSpouse(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSpouse() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SPOUSE, selectivelyDisclosable.getRelationshipSpouse());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipFatherInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipFatherInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_FATHER_IN_LAW, selectivelyDisclosable.getRelationshipFatherInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipMotherInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipMotherInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_MOTHER_IN_LAW, selectivelyDisclosable.getRelationshipMotherInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipParentInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParentInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENT_IN_LAW, selectivelyDisclosable.getRelationshipParentInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipSonInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipSonInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_SON_IN_LAW, selectivelyDisclosable.getRelationshipSonInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipDaughterInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipDaughterInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_DAUGHTER_IN_LAW, selectivelyDisclosable.getRelationshipDaughterInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipChildInLaw(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipChildInLaw() != null) {
                return create(ISO232202Headers.RELATIONSHIP_CHILD_IN_LAW, selectivelyDisclosable.getRelationshipChildInLaw());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipParentalAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipParentalAuthority() != null) {
                return create(ISO232202Headers.RELATIONSHIP_PARENTAL_AUTHORITY, selectivelyDisclosable.getRelationshipParentalAuthority());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipLegalRepresentative(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipLegalRepresentative() != null) {
                return create(ISO232202Headers.RELATIONSHIP_LEGAL_REPRESENTATIVE, selectivelyDisclosable.getRelationshipLegalRepresentative());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getRelationshipAgent(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getRelationshipAgent() != null) {
                return create(ISO232202Headers.RELATIONSHIP_AGENT, selectivelyDisclosable.getRelationshipAgent());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDocumentType(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentType() != null) {
                return create(ISO232202Headers.DOCUMENT_TYPE, selectivelyDisclosable.getDocumentType());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeIssuanceDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(ISO232202Headers.ISSUE_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getAdministrativeIssuanceDate()));
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeExpirationDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(ISO232202Headers.EXPIRY_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getAdministrativeExpirationDate()));
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to PID Rulebook specification.
     */
    protected static final class EUDIPIDEAAClaimsBuilder extends DefaultMdocEAAClaimsBuilder {

        /** Singleton */
        private static EUDIPIDEAAClaimsBuilder instance;

        /**
         * Default constructor
         */
        private EUDIPIDEAAClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link EUDIPIDEAAClaimsBuilder}
         */
        public static EUDIPIDEAAClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new EUDIPIDEAAClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.EUDI_PID_NAMESPACE;
        }

        @Override
        protected MdocEAAClaim getGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getGivenName() != null) {
                return create(EUDIPIDHeaders.GIVEN_NAME, selectivelyDisclosable.getGivenName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getFamilyName() != null) {
                return create(EUDIPIDHeaders.FAMILY_NAME, selectivelyDisclosable.getFamilyName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getEmail(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getEmail() != null) {
                return create(EUDIPIDHeaders.EMAIL_ADDRESS, selectivelyDisclosable.getEmail());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getSex(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getSex() != null) {
                return create(EUDIPIDHeaders.SEX, selectivelyDisclosable.getSex());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthdate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthdate() != null) {
                if (selectivelyDisclosable.getBirthdateApproximateMask() != null) {
                    return super.getBirthdate(selectivelyDisclosable);
                }
                return create(EUDIPIDHeaders.BIRTH_DATE, CBORUtils.toFullDate(selectivelyDisclosable.getBirthdate()));
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPlaceOfBirth(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPlaceOfBirthCountry() != null ||
                    selectivelyDisclosable.getPlaceOfBirthRegion() != null ||
                    selectivelyDisclosable.getPlaceOfBirthLocality() != null) {
                final CBORMap placeOfBirth = new CBORMap();
                if (selectivelyDisclosable.getPlaceOfBirthCountry() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_COUNTRY, selectivelyDisclosable.getPlaceOfBirthCountry());
                }
                if (selectivelyDisclosable.getPlaceOfBirthRegion() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_REGION, selectivelyDisclosable.getPlaceOfBirthRegion());
                }
                if (selectivelyDisclosable.getPlaceOfBirthLocality() != null) {
                    placeOfBirth.put(EUDIPIDHeaders.PLACE_OF_BIRTH_LOCALITY, selectivelyDisclosable.getPlaceOfBirthLocality());
                }
                return create(EUDIPIDHeaders.PLACE_OF_BIRTH, placeOfBirth);
            }
            return super.getPlaceOfBirth(selectivelyDisclosable);
        }

        @Override
        protected MdocEAAClaim getNationalities(MdocEAAClaimParameters selectivelyDisclosable) {
            if (Utils.isCollectionNotEmpty(selectivelyDisclosable.getNationalities())) {
                return create(EUDIPIDHeaders.NATIONALITY, selectivelyDisclosable.getNationalities());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthGivenName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthGivenName() != null) {
                return create(EUDIPIDHeaders.GIVEN_NAME_BIRTH, selectivelyDisclosable.getBirthGivenName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getBirthFamilyName(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getBirthFamilyName() != null) {
                return create(EUDIPIDHeaders.FAMILY_NAME_BIRTH, selectivelyDisclosable.getBirthFamilyName());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getMobilePhoneNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getMobilePhoneNumber() != null) {
                return create(EUDIPIDHeaders.MOBILE_PHONE_NUMBER, selectivelyDisclosable.getMobilePhoneNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingCountry() != null) {
                return create(EUDIPIDHeaders.ISSUING_COUNTRY, selectivelyDisclosable.getIssuingCountry());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingAuthority(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthority() != null) {
                return create(EUDIPIDHeaders.ISSUING_AUTHORITY, selectivelyDisclosable.getIssuingAuthority());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getDocumentNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getDocumentNumber() != null) {
                return create(EUDIPIDHeaders.DOCUMENT_NUMBER, selectivelyDisclosable.getDocumentNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPortrait(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPortrait() != null) {
                return create(EUDIPIDHeaders.PORTRAIT, selectivelyDisclosable.getPortrait());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPersonalAdministrativeNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPersonalAdministrativeNumber() != null) {
                return create(EUDIPIDHeaders.PERSONAL_ADMINISTRATIVE_NUMBER, selectivelyDisclosable.getPersonalAdministrativeNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPostalAddress(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPostalAddress() != null) {
                return create(EUDIPIDHeaders.RESIDENT_ADDRESS, selectivelyDisclosable.getPostalAddress());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingJurisdiction(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingJurisdiction() != null) {
                return create(EUDIPIDHeaders.ISSUING_JURISDICTION, selectivelyDisclosable.getIssuingJurisdiction());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCity(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCity() != null) {
                return create(EUDIPIDHeaders.RESIDENT_CITY, selectivelyDisclosable.getAddressCity());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressState(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressState() != null) {
                return create(EUDIPIDHeaders.RESIDENT_STATE, selectivelyDisclosable.getAddressState());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressPostalCode(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressPostalCode() != null) {
                return create(EUDIPIDHeaders.RESIDENT_POSTAL_CODE, selectivelyDisclosable.getAddressPostalCode());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressCountry(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressCountry() != null) {
                return create(EUDIPIDHeaders.RESIDENT_COUNTRY, selectivelyDisclosable.getAddressCountry());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeIssuanceDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeIssuanceDate() != null) {
                return create(EUDIPIDHeaders.ISSUANCE_DATE, selectivelyDisclosable.getAdministrativeIssuanceDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAdministrativeExpirationDate(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAdministrativeExpirationDate() != null) {
                return create(EUDIPIDHeaders.EXPIRY_DATE, selectivelyDisclosable.getAdministrativeExpirationDate());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressStreet(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressStreet() != null) {
                return create(EUDIPIDHeaders.RESIDENT_STREET, selectivelyDisclosable.getAddressStreet());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getResidentAddressHouseNumber(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAddressHouseNumber() != null) {
                return create(EUDIPIDHeaders.RESIDENT_HOUSE_NUMBER, selectivelyDisclosable.getAddressHouseNumber());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getTrustAnchor(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getTrustAnchor() != null) {
                return create(EUDIPIDHeaders.TRUST_ANCHOR, selectivelyDisclosable.getTrustAnchor());
            }
            return null;
        }

    }

    /**
     * Provides claim definitions for the document conformant to PID Rulebook specification.
     */
    protected static final class ETSI194721EAAClaimsBuilder extends DefaultMdocEAAClaimsBuilder {

        /** Singleton */
        private static ETSI194721EAAClaimsBuilder instance;

        /**
         * Default constructor
         */
        private ETSI194721EAAClaimsBuilder() {
            // empty
        }

        /**
         * Gets current instance
         *
         * @return {@link ETSI194721EAAClaimsBuilder}
         */
        public static ETSI194721EAAClaimsBuilder getInstance() {
            if (instance == null) {
                instance = new ETSI194721EAAClaimsBuilder();
            }
            return instance;
        }

        @Override
        public String getNamespace() {
            return MdocConstants.ETSI_19472_1_NAMESPACE;
        }

        @Override
        protected MdocEAAClaim getShortLived(MdocEAAPayloadParameters payloadParameters) {
            if (payloadParameters.isShortLived()) {
                return create(ETSI194721Headers.SHORT_LIVED, payloadParameters.isShortLived());
            }
            return null;
        }


        @Override
        protected MdocEAAClaim getOneTime(MdocEAAPayloadParameters payloadParameters) {
            if (payloadParameters.isOneTime()) {
                return create(ETSI194721Headers.ONE_TIME, payloadParameters.isOneTime());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getCategory(MdocEAAPayloadParameters payloadParameters) {
            if (payloadParameters.getCategory() != null) {
                return create(ETSI194721Headers.CATEGORY, payloadParameters.getCategory());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getPseudonym(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getPseudonym() != null) {
                return create(ETSI194721Headers.ALSO_KNOWN_AS, selectivelyDisclosable.getPseudonym());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getIssuingAuthorityRegistrationIdentifier(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier() != null) {
                return create(ETSI194721Headers.ISSUING_REGISTRATION_IDENTIFIER, selectivelyDisclosable.getIssuingAuthorityRegistrationIdentifier());
            }
            return null;
        }

        @Override
        protected MdocEAAClaim getAttestedAttributesSubject(MdocEAAClaimParameters selectivelyDisclosable) {
            if (selectivelyDisclosable.getAttestedAttributesSubjectFamilyName() != null &&
                    selectivelyDisclosable.getAttestedAttributesSubjectGivenName() != null &&
                    selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber() != null) {
                final CBORMap subAttr = new CBORMap();
                CBORMap subId = new CBORMap();
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_FAMILY_NAME, selectivelyDisclosable.getAttestedAttributesSubjectFamilyName());
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_GIVEN_NAME, selectivelyDisclosable.getAttestedAttributesSubjectGivenName());
                subId.put(ETSI194721Headers.SUB_ATTRS_ID_DOCUMENT_NUMBER, selectivelyDisclosable.getAttestedAttributesSubjectDocumentNumber());
                subAttr.put(ETSI194721Headers.SUB_ATTRS_ID, subId);
                return create(ETSI194721Headers.SUB_ATTRS, subAttr);

            } else if (selectivelyDisclosable.getAttestedAttributesSubjectPseudonym() != null) {
                final CBORMap subAttr = new CBORMap();
                subAttr.put(ETSI194721Headers.SUB_ATTRS_AKA, selectivelyDisclosable.getAttestedAttributesSubjectPseudonym());
                return create(ETSI194721Headers.SUB_ATTRS, subAttr);
            }
            return null;
        }

    }

}

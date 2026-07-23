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
package eu.europa.esig.dss.validation.process.bbb.sav;

import eu.europa.esig.dss.detailedreport.jaxb.XmlAOV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.diagnostic.EAARevocationWrapper;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.LevelRule;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.process.ChainItem;
import eu.europa.esig.dss.validation.process.eaa.checks.AcceptableEAARevocationFoundCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAAdministrativeExpirationDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAAdministrativeIssuanceDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAAdministrativePeriodNotExpiredCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAACategoryCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAClaimsCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAExpirationPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAIdentifierPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAIssuanceDatePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAIssuingAuthorityCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAIssuingAuthorityRegistrationIdentifierCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAIssuingCountryCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAANotBeforePresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAANotExpiredCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAANotOnHoldCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAANotRevokedCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAOneTimeUseCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAPseudonymUsageCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAARevocationAcceptableCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAARevocationAvailableCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAARevocationPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAARevocationStatusKnownCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAAShortLivedCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAASubjectCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAASubjectPseudonymCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAASupportedClaimsCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAASupportedNamespacesCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAATypeCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.EAATypeIntegrityPresentCheck;
import eu.europa.esig.dss.validation.process.eaa.checks.ETSI194721ConformanceCheck;

import java.util.Date;
import java.util.Map;

/**
 * Performs verification of EAA against the validationPolicy defined acceptance criteria
 *
 */
public class EAAAcceptanceValidation extends AbstractAcceptanceValidation<EAAWrapper> {

    /** A map of BasicBuildingBlocks */
    private final Map<String, XmlBasicBuildingBlocks> bbbs;

    /** Last acceptable EAA token status */
    private EAARevocationWrapper lastAcceptableStatus;

    /**
     * Default constructor
     *
     * @param i18nProvider {@link I18nProvider}
     * @param currentTime {@link Date} validation time
     * @param eaaWrapper {@link EAAWrapper}
     * @param bbbs a map of {@link XmlBasicBuildingBlocks}s
     * @param aov {@link XmlAOV}
     * @param validationPolicy {@link ValidationPolicy}
     */
    public EAAAcceptanceValidation(I18nProvider i18nProvider, Date currentTime,
                                   EAAWrapper eaaWrapper, Map<String, XmlBasicBuildingBlocks> bbbs, XmlAOV aov,
                                   ValidationPolicy validationPolicy) {
        super(i18nProvider, eaaWrapper, currentTime, Context.EAA, aov, validationPolicy);
        this.bbbs = bbbs;
    }

    @Override
    protected MessageTag getTitle() {
        return MessageTag.SIGNATURE_ACCEPTANCE_VALIDATION;
    }

    @Override
    protected void initChain() {
        ChainItem<XmlSAV> item = firstItem = etsi194721Conformance();

        item = item.setNextItem(eaaType());
        if (EAAType.SD_JWT_VC == token.getEAAType()) {
            item = item.setNextItem(typeIntegrityPresent());
        }

        if (EAAType.ISO_IEC_MDOC == token.getEAAType()) {
            item = item.setNextItem(issuanceDatePresent());
        }

        item = item.setNextItem(eaaIdentifierPresent());

        item = item.setNextItem(notBeforePresent());

        item = item.setNextItem(expirationPresent());

        if (token.getNotBefore() != null && token.getExpiration() != null) {
            item = item.setNextItem(notExpired());
        }

        item = item.setNextItem(administrativeIssuanceDatePresent());

        item = item.setNextItem(administrativeExpirationDatePresent());

        if (token.getAdministrativeIssuanceDate() != null && token.getAdministrativeExpirationDate() != null) {
            item = item.setNextItem(administrativePeriodNotExpired());
        }

        item = item.setNextItem(category());

        item = item.setNextItem(subject());

        item = item.setNextItem(subjectPseudonym());

        item = item.setNextItem(issuingCountry());

        item = item.setNextItem(issuingAuthority());

        item = item.setNextItem(issuingAuthorityRegistrationIdentifier());

        if (Utils.isTrue(token.getOneTimeUse())) {
            item = item.setNextItem(oneTimeUse());
        }

        if (Utils.isTrue(token.getShortLived())) {

            item = item.setNextItem(shortLived());

        } else {

            // TODO : make status check configurable ?

            EAARevocationPresentCheck revocationPresentCheck = statusPresent();

            item = item.setNextItem(revocationPresentCheck);

            if (revocationPresentCheck.process()) {

                item = item.setNextItem(statusAvailable());

                // TODO : improve with EAA Status selector ?
                lastAcceptableStatus = null;
                for (EAARevocationWrapper revocationWrapper : token.getAttestationRevocations()) {

                    XmlBasicBuildingBlocks eaaRevocationBBB = bbbs.get(revocationWrapper.getId());
                    if (eaaRevocationBBB == null) {
                        throw new IllegalStateException(String.format("No BasicBuildingBlock found for token with Id '%s'", revocationWrapper.getId()));
                    }

                    item = item.setNextItem(statusKnown(revocationWrapper));

                    item = item.setNextItem(statusAcceptable(revocationWrapper, eaaRevocationBBB.getConclusion()));

                    if (isValidConclusion(eaaRevocationBBB.getConclusion())
                            && (lastAcceptableStatus == null || lastAcceptableStatus.getIssuedAt().before(revocationWrapper.getIssuedAt()))) {
                        lastAcceptableStatus = revocationWrapper;
                    }

                }

                item = item.setNextItem(acceptableStatusFound(lastAcceptableStatus));

                if (lastAcceptableStatus != null) {

                    item = item.setNextItem(notRevoked(lastAcceptableStatus));

                    item = item.setNextItem(notOnHold(lastAcceptableStatus));

                }

            }

        }

        if (token.getPseudonym() != null) {
            item = item.setNextItem(usePseudonym());
        }

        item = item.setNextItem(claims());

        item = item.setNextItem(supportedClaims());

        if (EAAType.ISO_IEC_MDOC == token.getEAAType()) {

            item = item.setNextItem(supportedNamespaces());

        }

        // cryptographic check
        item = cryptographic(item);

    }

    private ChainItem<XmlSAV> etsi194721Conformance() {
        LevelRule constraint = validationPolicy.getEAAETSI194721ConformanceConstraint();
        return new ETSI194721ConformanceCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> eaaType() {
        MultiValuesRule constraint = validationPolicy.getEAATypeConstraint();
        return new EAATypeCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> typeIntegrityPresent() {
        LevelRule constraint = validationPolicy.getEAATypeIntegrityPresentConstraint();
        return new EAATypeIntegrityPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> notBeforePresent() {
        LevelRule constraint = validationPolicy.getEAANotBeforePresentConstraint();
        return new EAANotBeforePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> expirationPresent() {
        LevelRule constraint = validationPolicy.getEAAExpirationPresentConstraint();
        return new EAAExpirationPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> notExpired() {
        LevelRule constraint = validationPolicy.getEAANotExpiredConstraint();
        return new EAANotExpiredCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> administrativeIssuanceDatePresent() {
        LevelRule constraint = validationPolicy.getEAAAdministrativeIssuanceDatePresentConstraint();
        return new EAAAdministrativeIssuanceDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> administrativeExpirationDatePresent() {
        LevelRule constraint = validationPolicy.getEAAAdministrativeExpirationDatePresentConstraint();
        return new EAAAdministrativeExpirationDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> administrativePeriodNotExpired() {
        LevelRule constraint = validationPolicy.getEAAAdministrativePeriodNotExpiredConstraint();
        return new EAAAdministrativePeriodNotExpiredCheck(i18nProvider, result, token, currentTime, constraint);
    }

    private ChainItem<XmlSAV> eaaIdentifierPresent() {
        LevelRule constraint = validationPolicy.getEAAIdentifierPresentConstraint();
        return new EAAIdentifierPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuanceDatePresent() {
        LevelRule constraint = validationPolicy.getEAAIssuanceDatePresentConstraint();
        return new EAAIssuanceDatePresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> category() {
        MultiValuesRule constraint = validationPolicy.getEAACategoryConstraint();
        return new EAACategoryCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> subject() {
        MultiValuesRule constraint = validationPolicy.getEAASubjectConstraint();
        return new EAASubjectCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> subjectPseudonym() {
        MultiValuesRule constraint = validationPolicy.getEAASubjectPseudonymConstraint();
        return new EAASubjectPseudonymCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingCountry() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingCountryConstraint();
        return new EAAIssuingCountryCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingAuthority() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingAuthorityConstraint();
        return new EAAIssuingAuthorityCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> issuingAuthorityRegistrationIdentifier() {
        MultiValuesRule constraint = validationPolicy.getEAAIssuingAuthorityRegistrationIdentifierConstraint();
        return new EAAIssuingAuthorityRegistrationIdentifierCheck(i18nProvider, result, token, constraint);
    }

    private EAARevocationPresentCheck statusPresent() {
        LevelRule constraint = validationPolicy.getEAARevocationPresentConstraint();
        return new EAARevocationPresentCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> statusAvailable() {
        LevelRule constraint = validationPolicy.getEAARevocationAvailableConstraint();
        return new EAARevocationAvailableCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> statusKnown(EAARevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationUnknownStatusConstraint();
        return new EAARevocationStatusKnownCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> statusAcceptable(EAARevocationWrapper eaaRevocationWrapper, XmlConclusion xmlConclusion) {
        return new EAARevocationAcceptableCheck(i18nProvider, result, eaaRevocationWrapper, xmlConclusion, getWarnLevelRule());
    }

    private ChainItem<XmlSAV> acceptableStatusFound(EAARevocationWrapper acceptableEAARevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationAvailableConstraint();
        return new AcceptableEAARevocationFoundCheck(i18nProvider, result, acceptableEAARevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> notRevoked(EAARevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationNotRevokedConstraint();
        return new EAANotRevokedCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> notOnHold(EAARevocationWrapper eaaRevocationWrapper) {
        LevelRule constraint = validationPolicy.getEAARevocationNotOnHoldConstraint();
        return new EAANotOnHoldCheck(i18nProvider, result, eaaRevocationWrapper, constraint);
    }

    private ChainItem<XmlSAV> shortLived() {
        LevelRule constraint = validationPolicy.getEAAShortLivedConstraint();
        return new EAAShortLivedCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> oneTimeUse() {
        LevelRule constraint = validationPolicy.getEAAOneTimeUseConstraint();
        return new EAAOneTimeUseCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> usePseudonym() {
        LevelRule constraint = validationPolicy.getEAAUsePseudonymConstraint();
        return new EAAPseudonymUsageCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> claims() {
        MultiValuesRule constraint = validationPolicy.getEAAClaimsConstraint();
        return new EAAClaimsCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> supportedClaims() {
        MultiValuesRule constraint = validationPolicy.getEAASupportedClaimsConstraint();
        return new EAASupportedClaimsCheck(i18nProvider, result, token, constraint);
    }

    private ChainItem<XmlSAV> supportedNamespaces() {
        MultiValuesRule constraint = validationPolicy.getEAASupportedNamespacesConstraint();
        return new EAASupportedNamespacesCheck(i18nProvider, result, token, constraint);
    }

    @Override
    protected void collectMessages(XmlConclusion conclusion, XmlConstraint constraint) {
        if (!MessageTag.EAA_REV_ACC.getId().equals(constraint.getName().getKey())) {
            super.collectMessages(conclusion, constraint);
        }
    }

    @Override
    protected void collectAdditionalMessages(XmlConclusion conclusion) {
        super.collectAdditionalMessages(conclusion);

        if (lastAcceptableStatus != null) {
            XmlBasicBuildingBlocks tokenBBB = bbbs.get(lastAcceptableStatus.getId());
            collectAllMessages(conclusion, tokenBBB.getConclusion());
        } else {
            for (EAARevocationWrapper EAARevocationWrapper : token.getAttestationRevocations()) {
                XmlBasicBuildingBlocks tokenBBB = bbbs.get(EAARevocationWrapper.getId());
                collectAllMessages(conclusion, tokenBBB.getConclusion());
            }
        }
    }

}

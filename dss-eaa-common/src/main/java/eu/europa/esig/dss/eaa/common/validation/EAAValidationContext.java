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

import eu.europa.esig.dss.spi.eaa.EAA;
import eu.europa.esig.dss.spi.eaa.EAAPresentation;
import eu.europa.esig.dss.spi.eaa.EAARevocationToken;
import eu.europa.esig.dss.spi.eaa.status.EAARevocationSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.SignatureValidationContext;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Performs validation of EAA tokens. During validation, retrieved the corresponding information,
 * including the data required for a signature validation, and/or EAA revocation verification.
 */
public class EAAValidationContext extends SignatureValidationContext {

    private static final Logger LOG = LoggerFactory.getLogger(EAAValidationContext.class);

    /**
     * EAA Presentation to process
     */
    private EAAPresentation processedEAAPresentation;

    /**
     * A set of EAAPresentation Status tokens to process
     */
    private final Set<EAARevocationToken> processedEAARevocationTokens = new LinkedHashSet<>();

    /**
     * Source used to verify status of the EAAPresentation
     */
    private EAARevocationSource EAARevocationSource;

    /**
     * Default constructor instantiating object with null or empty values and current time
     */
    public EAAValidationContext() {
        this(new Date());
    }

    /**
     * Constructor instantiating object with null or empty values and provided time
     *
     * @param validationTime {@link Date} validation time to be used during the execution
     */
    public EAAValidationContext(Date validationTime) {
        super(validationTime);
    }

    /**
     * Sets the EAAStatusSource used for retrieving an information about a status of the EAAPresentations
     *
     * @param EAARevocationSource {@link EAARevocationSource}
     */
    public void setEAAStatusSource(EAARevocationSource EAARevocationSource) {
        this.EAARevocationSource = EAARevocationSource;
    }

    /**
     * Adds an {@code EAAPresentation} to be verified
     *
     * @param eaaPresentation {@link EAAPresentation}
     */
    public void addEAAPresentationForVerification(final EAAPresentation eaaPresentation) {
        if (eaaPresentation == null) {
            return;
        }
        if (processedEAAPresentation != null) {
            throw new IllegalStateException("EAA Presentation was already added to EAAValidationContext! " +
                    "Only one EAAPresentation is supported per validation.");
        }

        addEAAPresentationCertificateSources(eaaPresentation);

        prepareSignatures(eaaPresentation);

        processedEAAPresentation = eaaPresentation;
        if (LOG.isTraceEnabled()) {
            LOG.trace("EAAPresentation added to EAAValidationContext");
        }
    }

    private void addEAAPresentationCertificateSources(EAAPresentation eaaPresentation) {
        for (EAA eaa : eaaPresentation.getElectronicAttestationsOfAttributes()) {
            CertificateSource deviceKeyCertificateSource = eaa.getDeviceKeyCertificateSource();
            if (deviceKeyCertificateSource != null) {
                addDocumentCertificateSource(deviceKeyCertificateSource);
            }
        }
    }

    private void prepareSignatures(EAAPresentation eaaPresentation) {
        for (EAA eaa : eaaPresentation.getElectronicAttestationsOfAttributes()) {
            List<AdvancedSignature> signatures = eaa.getSignatures();
            if (Utils.isCollectionNotEmpty(signatures)) {
                for (AdvancedSignature signature : signatures) {
                    addSignatureForVerification(signature);
                }
            }
            AdvancedSignature keyBindingSignature = eaa.getKeyBindingSignature();
            if (keyBindingSignature != null) {
                addSignatureForVerification(keyBindingSignature);
            }
        }
    }

    /**
     * Adds an {@code EAAStatusToken} to be verified
     *
     * @param eaaRevocationToken {@link EAARevocationToken}
     */
    public void addEAAStatusTokenForVerification(final EAARevocationToken eaaRevocationToken) {
        if (eaaRevocationToken == null) {
            return;
        }

        addSignatureForVerification(eaaRevocationToken.getSignature());
        addDocumentCertificateSource(eaaRevocationToken.getCertificateSource());

        final boolean added = processedEAARevocationTokens.add(eaaRevocationToken);
        if (LOG.isTraceEnabled()) {
            if (added) {
                LOG.trace("EAAPresentation Status Token added to processedEAAStatusTokens: {} ", eaaRevocationToken.getDSSIdAsString());
            } else {
                LOG.trace("EAAPresentation already present processedEAAStatusTokens: {} ", eaaRevocationToken.getDSSIdAsString());
            }
        }
    }

    @Override
    public void validate() {
        if (processedEAAPresentation != null) {
            for (EAA eaa : processedEAAPresentation.getElectronicAttestationsOfAttributes()) {
                findEAAStatusData(eaa);
            }
        }
        super.validate();
    }

    /**
     * Fetches the EAAPresentation status token for the {@code EAAPresentation}, when required
     *
     * @param eaa {@link EAA} to get status for
     */
    private void findEAAStatusData(EAA eaa) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("Checking status data for : {}", eaa.getId());
        }

        if (isEAAStatusCheckRequired(eaa)) {
            if (EAARevocationSource == null) {
                LOG.info("No EAAStatusSource has been provided. EAA status check is skipped.");
                return;
            }
            if (LOG.isTraceEnabled()) {
                LOG.trace("EAAPresentation status check is in progress for EAAPresentation : {}", eaa.getId());
            }

            EAARevocationToken eaaRevocationToken = EAARevocationSource.getEAARevocation(eaa);
            if (eaaRevocationToken != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Obtained a new EAAPresentation Status token : {}, for EAAPresentation : {}",
                            eaaRevocationToken.getDSSIdAsString(), eaa.getId());
                }
                addEAAStatusTokenForVerification(eaaRevocationToken);
            }

        } else if (LOG.isDebugEnabled()) {
            LOG.debug("Status data is not required for EAAPresentation : {}", eaa.getId());
        }
    }

    /**
     * This method verifies whether the {@code EAAPresentation} requires the status verification
     *
     * @param eaa {@link EAA}
     * @return TRUE if the EAAPresentation status should be checked, FALSE otherwise
     */
    protected boolean isEAAStatusCheckRequired(EAA eaa) {
        if (eaa.getPayload() != null && eaa.getPayload().getShortLived() != null) {
            Boolean shortLived = eaa.getPayload().getShortLived().getBooleanValue();
            return shortLived != null && !Utils.isTrue(shortLived);
        }
        return true;
    }

    /**
     * Gets an EAAPresentations validated by the context
     *
     * @return {@link EAAPresentation}
     */
    public EAAPresentation getProcessedEAAPresentation() {
        return  processedEAAPresentation;
    }

    /**
     * Gets a set of EAAPresentation Status Tokens validated by the context
     *
     * @return a set of {@link EAARevocationToken}s
     */
    public Set<EAARevocationToken> getProcessedEAAStatusTokens() {
        return Collections.unmodifiableSet(processedEAARevocationTokens);
    }

    @Override
    public Set<AdvancedSignature> getProcessedSignatures() {
        // exclude EAA revocation signatures
        Set<AdvancedSignature> processedSignatures = super.getProcessedSignatures();
        if (Utils.isCollectionEmpty(processedEAARevocationTokens)) {
            return processedSignatures;
        }
        final Set<AdvancedSignature> result = new HashSet<>();
        for (AdvancedSignature advancedSignature : processedSignatures) {
            if (processedEAARevocationTokens.stream().noneMatch(t -> t.getSignature() != null
                    && advancedSignature.getId().equals(t.getSignature().getId()))) {
                result.add(advancedSignature);
            }
        }
        return result;
    }

}

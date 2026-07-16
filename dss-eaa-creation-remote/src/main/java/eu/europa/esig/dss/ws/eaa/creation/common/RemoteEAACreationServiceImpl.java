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
package eu.europa.esig.dss.ws.eaa.creation.common;

import eu.europa.esig.dss.eaa.common.creation.EAADisclosure;
import eu.europa.esig.dss.eaa.common.creation.EAAPayloadParameters;
import eu.europa.esig.dss.eaa.common.creation.EAAService;
import eu.europa.esig.dss.eaa.common.creation.KeyBindingParameters;
import eu.europa.esig.dss.eaa.sd.jwt.creation.SDJWTEAAService;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAADeviceSignedParameters;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAADisclosure;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAService;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.SerializableSignatureParameters;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.ws.converter.DTOConverter;
import eu.europa.esig.dss.ws.converter.RemoteDocumentConverter;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;
import eu.europa.esig.dss.ws.dto.ToBeSignedDTO;
import eu.europa.esig.dss.ws.eaa.creation.common.builder.RemoteEAACreationSignatureParametersBuilder;
import eu.europa.esig.dss.ws.eaa.creation.common.builder.RemoteEAAPayloadParametersBuilder;
import eu.europa.esig.dss.ws.eaa.creation.common.builder.RemoteEAAPresentationParametersBuilder;
import eu.europa.esig.dss.ws.eaa.creation.common.builder.RemoteKeyBindingParametersBuilder;
import eu.europa.esig.dss.ws.eaa.creation.common.converter.DisclosureFromDTOConverter;
import eu.europa.esig.dss.ws.eaa.creation.common.converter.DisclosureToDTOConverter;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DisclosureDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.RemoteEAAPayloadParameters;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.RemoteEAAPresentationParameters;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.RemoteKeyBindingParameters;
import eu.europa.esig.dss.ws.signature.dto.parameters.RemoteSignatureParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Default implementation of the {@code eu.europa.esig.dss.ws.eaa.creation.common.RemoteEAACreationService}
 *
 */
public class RemoteEAACreationServiceImpl implements RemoteEAACreationService {

    private static final long serialVersionUID = -8392274758014040836L;

    private static final Logger LOG = LoggerFactory.getLogger(RemoteEAACreationServiceImpl.class);

    /**
     * SD-JWT VC service
     */
    private SDJWTEAAService sdjwtService;

    /**
     * Mdoc EAA service
     */
    private MdocEAAService mdocService;

    /**
     * Default constructor
     */
    public RemoteEAACreationServiceImpl() {
        // empty
    }

    /**
     * Sets the SD-JWT VC EAA service
     *
     * @param sdjwtService {@link SDJWTEAAService}
     */
    public void setSdjwtService(SDJWTEAAService sdjwtService) {
        this.sdjwtService = sdjwtService;
    }

    /**
     * Sets the mdoc service
     *
     * @param mdocService {@link MdocEAAService}
     */
    public void setMdocService(MdocEAAService mdocService) {
        this.mdocService = mdocService;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSign(RemoteEAAPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getEaaType(), "eaaType must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSign for EAA signature in process...");

        SerializableSignatureParameters parameters = new RemoteEAACreationSignatureParametersBuilder(payloadParameters.getEaaType(), signatureParameters).build();
        EAAService eaaService = getEAAServiceForType(payloadParameters.getEaaType());

        ToBeSigned toBeSigned;
        if (payloadParameters.getPreComputedPayload() != null) {
            DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(payloadParameters.getPreComputedPayload());
            toBeSigned = eaaService.getDataToBeSigned(dssDocument, parameters);
        } else {
            EAAPayloadParameters eaaPayloadParameters = new RemoteEAAPayloadParametersBuilder(payloadParameters).build();
            toBeSigned = eaaService.getDataToBeSigned(eaaPayloadParameters, parameters);
        }
        LOG.info("GetDataToSign for EAA signature is finished");
        return DTOConverter.toToBeSignedDTO(toBeSigned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument signEAA(RemoteEAAPayloadParameters payloadParameters, RemoteSignatureParameters signatureParameters,
                                  SignatureValueDTO signatureValueDTO) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getEaaType(), "eaaType must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "signatureValue must be defined!");
        LOG.info("SignEAA in process...");

        SerializableSignatureParameters parameters = new RemoteEAACreationSignatureParametersBuilder(payloadParameters.getEaaType(), signatureParameters).build();
        EAAService eaaService = getEAAServiceForType(payloadParameters.getEaaType());

        DSSDocument signedEAA;
        if (payloadParameters.getPreComputedPayload() != null) {
            DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(payloadParameters.getPreComputedPayload());
            signedEAA = eaaService.signEAA(dssDocument, parameters, toSignatureValue(signatureValueDTO));
        } else {
            EAAPayloadParameters eaaPayloadParameters = new RemoteEAAPayloadParametersBuilder(payloadParameters).build();
            signedEAA = eaaService.signEAA(eaaPayloadParameters, parameters, toSignatureValue(signatureValueDTO));
        }
        LOG.info("SignEAA is finished");
        return RemoteDocumentConverter.toRemoteDocument(signedEAA);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public List<DisclosureDTO> getDisclosures(RemoteEAAPayloadParameters payloadParameters) throws DSSException {
        Objects.requireNonNull(payloadParameters, "payloadParameters must be defined!");
        Objects.requireNonNull(payloadParameters.getEaaType(), "eaaType must be defined!");
        LOG.info("GetDisclosures in process...");

        EAAService eaaService = getEAAServiceForType(payloadParameters.getEaaType());
        EAAPayloadParameters eaaPayloadParameters = new RemoteEAAPayloadParametersBuilder(payloadParameters).build();

        List<? extends EAADisclosure> disclosures = eaaService.getDisclosures(eaaPayloadParameters);
        List<DisclosureDTO> disclosureDTOs = disclosures.stream().map(new DisclosureToDTOConverter()).collect(Collectors.toList());

        LOG.info("GetDisclosures is finished");
        return disclosureDTOs;
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public ToBeSignedDTO getDataToSignForKeyBindingSignature(RemoteDocument eaa, List<DisclosureDTO> disclosureDTOs,
                                                             RemoteKeyBindingParameters keyBindingParametersDTO, RemoteSignatureParameters signatureParameters) throws DSSException {
        Objects.requireNonNull(eaa, "EAA must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO, "keyBindingParameters must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO.getEaaType(), "eaaType must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        LOG.info("GetDataToSignForKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteEAACreationSignatureParametersBuilder(keyBindingParametersDTO.getEaaType(), signatureParameters).build();
        EAAService eaaService = getEAAServiceForType(keyBindingParametersDTO.getEaaType());

        List<EAADisclosure> disclosures = toEAADisclosures(keyBindingParametersDTO.getEaaType(), disclosureDTOs);

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(eaa);

        ToBeSigned toBeSigned = eaaService.getDataToSignForKeyBindingSignature(dssDocument, disclosures, keyBindingParameters, parameters);
        LOG.info("GetDataToSignForKeyBindingSignature is finished");
        return DTOConverter.toToBeSignedDTO(toBeSigned);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument createKeyBindingSignature(RemoteDocument eaa, List<DisclosureDTO> disclosureDTOs, RemoteKeyBindingParameters keyBindingParametersDTO,
                                                    RemoteSignatureParameters signatureParameters, SignatureValueDTO signatureValueDTO) throws DSSException {
        Objects.requireNonNull(eaa, "EAA must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO, "keyBindingParameters must be defined!");
        Objects.requireNonNull(keyBindingParametersDTO.getEaaType(), "eaaType must be defined!");
        Objects.requireNonNull(signatureParameters, "signatureParameters must be defined!");
        Objects.requireNonNull(signatureValueDTO, "signatureValue must be defined!");
        LOG.info("CreateKeyBindingSignature in process...");

        KeyBindingParameters keyBindingParameters = new RemoteKeyBindingParametersBuilder(keyBindingParametersDTO).build();
        SerializableSignatureParameters parameters = new RemoteEAACreationSignatureParametersBuilder(keyBindingParametersDTO.getEaaType(), signatureParameters).build();
        EAAService eaaService = getEAAServiceForType(keyBindingParametersDTO.getEaaType());

        List<EAADisclosure> disclosures = toEAADisclosures(keyBindingParametersDTO.getEaaType(), disclosureDTOs);

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(eaa);

        DSSDocument keyBindingSignature = eaaService.createKeyBindingSignature(
                dssDocument, disclosures, keyBindingParameters, parameters, toSignatureValue(signatureValueDTO));
        LOG.info("CreateKeyBindingSignature is finished");
        return RemoteDocumentConverter.toRemoteDocument(keyBindingSignature);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Override
    public RemoteDocument issuePresentation(RemoteDocument eaa, List<DisclosureDTO> disclosureDTOs,
                                            RemoteDocument keyBinding, RemoteEAAPresentationParameters presentationParameters) throws DSSException {
        Objects.requireNonNull(eaa, "EAA must be defined!");
        Objects.requireNonNull(presentationParameters, "presentationParameters must be defined!");
        Objects.requireNonNull(presentationParameters.getEaaType(), "eaaType must be defined!");
        LOG.info("IssuePresentation in process...");

        DSSDocument dssDocument = RemoteDocumentConverter.toDSSDocument(eaa);
        DSSDocument keyBindingDocument = RemoteDocumentConverter.toDSSDocument(keyBinding);
        List<EAADisclosure> disclosures = toEAADisclosures(presentationParameters.getEaaType(), disclosureDTOs);
        EAAService eaaService = getEAAServiceForType(presentationParameters.getEaaType());
        DSSDocument eaaPresentation;
        switch (presentationParameters.getEaaType()) {
            case SD_JWT_VC:
                eaaPresentation = eaaService.issuePresentation(dssDocument, disclosures, keyBindingDocument);
                break;
            case ISO_IEC_MDOC:
                List<MdocEAADisclosure> mdocEAADisclosures = disclosures.stream().map(d -> (MdocEAADisclosure) d).collect(Collectors.toList());
                MdocEAADeviceSignedParameters deviceSignedParameters = new RemoteEAAPresentationParametersBuilder(
                        presentationParameters).buildMdocEAADeviceSignedParameters();
                eaaPresentation = ((MdocEAAService) eaaService).issuePresentation(
                        dssDocument, mdocEAADisclosures, keyBindingDocument, deviceSignedParameters);
                break;
            default:
                throw new UnsupportedOperationException(String.format(
                        "Unsupported EAA format: '%s'. SD-JWT VC and ISO/IEC mdoc are only supported.", presentationParameters.getEaaType()));
        }
        LOG.info("IssuePresentation is finished");
        return RemoteDocumentConverter.toRemoteDocument(eaaPresentation);
    }

    /**
     * Transforms {@code SignatureValueDTO} to {@code SignatureValue}
     *
     * @param signatureValueDTO {@link SignatureValueDTO}
     * @return {@link SignatureValue}
     */
    protected SignatureValue toSignatureValue(SignatureValueDTO signatureValueDTO) {
        return new SignatureValue(signatureValueDTO.getAlgorithm(), signatureValueDTO.getValue());
    }

    private List<EAADisclosure> toEAADisclosures(EAAType eaaType, List<DisclosureDTO> disclosureDTOs) {
        if (disclosureDTOs != null && !disclosureDTOs.isEmpty()) {
            return disclosureDTOs.stream().map(
                    new DisclosureFromDTOConverter(eaaType)).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    @SuppressWarnings("rawtypes")
    private EAAService getEAAServiceForType(EAAType eaaType) {
        EAAService eaaService;
        switch (eaaType) {
            case SD_JWT_VC:
                eaaService = sdjwtService;
                break;
            case ISO_IEC_MDOC:
                eaaService = mdocService;
                break;
            default:
                throw new UnsupportedOperationException(String.format(
                        "Unsupported EAA format: '%s'. SD-JWT VC and ISO/IEC mdoc are only supported.", eaaType));
        }
        if (eaaService == null) {
            throw new NullPointerException(String.format("No service has been provided for the EAA type '%s'", eaaType));
        }
        return eaaService;
    }

}

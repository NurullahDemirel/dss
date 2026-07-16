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
package eu.europa.esig.dss.ws.eaa.creation.common.converter;

import eu.europa.esig.dss.eaa.common.creation.EAADisclosure;
import eu.europa.esig.dss.eaa.sd.jwt.creation.SDJWTEAADisclosure;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAADisclosure;
import eu.europa.esig.dss.enumerations.EAAType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.DisclosureDTO;

import java.util.Objects;
import java.util.function.Function;

/**
 * Converts a {@code DisclosureDTO} into {@code EAADisclosure} of a corresponding format
 */
public class DisclosureFromDTOConverter implements Function<DisclosureDTO, EAADisclosure> {

    /** EAA Type */
    private final EAAType eaaType;

    /**
     * Default constructor
     *
     * @param eaaType {@link EAAType} to create a corresponding implementation of disclosures
     */
    public DisclosureFromDTOConverter(final EAAType eaaType) {
        Objects.requireNonNull(eaaType, "eaaType is mandatory!");
        this.eaaType = eaaType;
    }

    @Override
    public EAADisclosure apply(DisclosureDTO disclosureDTO) {
        switch (eaaType) {
            case SD_JWT_VC:
                return new SDJWTEAADisclosure(disclosureDTO.getValue());
            case ISO_IEC_MDOC:
                return new MdocEAADisclosure(disclosureDTO.getNamespace(), disclosureDTO.getDigestId(), Utils.fromBase64(disclosureDTO.getValue()));
            default:
                throw new UnsupportedOperationException(String.format("The EAA Type '%s' is not supported!", eaaType));
        }
    }

}

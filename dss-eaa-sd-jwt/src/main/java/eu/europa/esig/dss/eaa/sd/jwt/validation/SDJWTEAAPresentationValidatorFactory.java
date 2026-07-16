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
package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.eaa.common.validation.EAAPresentationValidatorFactory;
import eu.europa.esig.dss.model.DSSDocument;

/**
 * This class is used to load a relevant validator for a presentation of Electronic Attestation of Attributes validation
 *
 */
public class SDJWTEAAPresentationValidatorFactory implements EAAPresentationValidatorFactory {

    /**
     * Default constructor
     */
    public SDJWTEAAPresentationValidatorFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTCompactEAAPresentationValidator compactValidator = new SDJWTCompactEAAPresentationValidator();
        if (compactValidator.isSupported(document)) {
            return true;
        }

        SDJWTJsonSerializationEAAPresentationValidator jsonSerializationValidator = new SDJWTJsonSerializationEAAPresentationValidator();
        if (jsonSerializationValidator.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public AbstractSDJWTEAAPresentationValidator create(DSSDocument document) {
        SDJWTCompactEAAPresentationValidator compactValidator = new SDJWTCompactEAAPresentationValidator();
        if (compactValidator.isSupported(document)) {
            return new SDJWTCompactEAAPresentationValidator(document);
        }

        SDJWTJsonSerializationEAAPresentationValidator jsonSerializationValidator = new SDJWTJsonSerializationEAAPresentationValidator();
        if (jsonSerializationValidator.isSupported(document)) {
            return new SDJWTJsonSerializationEAAPresentationValidator(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}
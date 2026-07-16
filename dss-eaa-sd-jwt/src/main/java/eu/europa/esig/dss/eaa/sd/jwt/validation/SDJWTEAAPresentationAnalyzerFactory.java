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

import eu.europa.esig.dss.eaa.common.validation.DefaultEAAPresentationAnalyzer;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.validation.analyzer.eaa.EAAPresentationAnalyzerFactory;

/**
 * This class is used to load a corresponding {@code eu.europa.esig.dss.spi.validation.analyzer.eaa.EAAPresentationAnalyzer}
 * for an SD-JWT VC validation
 *
 */
public class SDJWTEAAPresentationAnalyzerFactory implements EAAPresentationAnalyzerFactory {

    /**
     * Default constructor
     */
    public SDJWTEAAPresentationAnalyzerFactory() {
        // empty
    }

    @Override
    public boolean isSupported(DSSDocument document) {
        SDJWTCompactEAAPresentationAnalyzer compactAnalyzer = new SDJWTCompactEAAPresentationAnalyzer();
        if (compactAnalyzer.isSupported(document)) {
            return true;
        }

        SDJWTJsonSerializationEAAPresentationAnalyzer jsonSerializationAnalyzer = new SDJWTJsonSerializationEAAPresentationAnalyzer();
        if (jsonSerializationAnalyzer.isSupported(document)) {
            return true;
        }

        return false;
    }

    @Override
    public DefaultEAAPresentationAnalyzer create(DSSDocument document) {
        SDJWTCompactEAAPresentationAnalyzer compactAnalyzer = new SDJWTCompactEAAPresentationAnalyzer();
        if (compactAnalyzer.isSupported(document)) {
            return new SDJWTCompactEAAPresentationAnalyzer(document);
        }

        SDJWTJsonSerializationEAAPresentationAnalyzer jsonSerializationAnalyzer = new SDJWTJsonSerializationEAAPresentationAnalyzer();
        if (jsonSerializationAnalyzer.isSupported(document)) {
            return new SDJWTJsonSerializationEAAPresentationAnalyzer(document);
        }

        throw new IllegalArgumentException("Not supported document");
    }

}

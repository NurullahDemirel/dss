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
package eu.europa.esig.dss.cookbook.example.snippets;

import eu.europa.esig.dss.eaa.common.validation.DefaultEAAPresentationValidator;
import eu.europa.esig.dss.eaa.jwt.creation.SDJWTEAAPayloadParameters;
import eu.europa.esig.dss.eaa.jwt.creation.SDJWTEAAClaim;
import eu.europa.esig.dss.eaa.jwt.creation.SDJWTEAAPayloadBuilder;
import eu.europa.esig.dss.eaa.jwt.creation.SDJWTEAAService;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAPayloadBuilder;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAService;
import eu.europa.esig.dss.eaa.mdoc.creation.MdocEAAClaim;
import eu.europa.esig.dss.eaa.mdoc.validation.MdocDeviceResponseEAAPresentationValidator;
import eu.europa.esig.dss.eaa.revocation.source.ExternalResourcesEAARevocationSource;
import eu.europa.esig.dss.eaa.revocation.source.OnlineEAARevocationSource;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

import java.security.SecureRandom;

public class EAASnippet {

    public static void main(String[] args) {

        SDJWTEAAPayloadParameters payloadParameters = new SDJWTEAAPayloadParameters();

        // tag::status-list[]
        // IETF draft-ietf-oauth-status-list: simple index + URL
        payloadParameters.setStatusList(42, "https://example.com/statuslists/1");

        // ETSI TS 119 472-1 v1.2.1 variant with type, purpose, index and URL
        payloadParameters.setStatusList("TokenStatusList", "revocation", 42, "https://example.com/statuslists/1");
        // end::status-list[]

        // tag::sdjwt-custom-salt[]
        // Provide an explicit base64url-encoded salt for a specific custom claim
        SDJWTEAAClaim claimWithSalt = SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("given_name", "John", "2GLC42sKQveCfGfryNRN9w");
        payloadParameters.selectivelyDisclosable().addClaim(claimWithSalt);
        // end::sdjwt-custom-salt[]

        // tag::sdjwt-custom-secure-random[]
        // Replace the default deterministic SecureRandomProvider with a fully non-deterministic one
        SDJWTEAAPayloadBuilder payloadBuilder = new SDJWTEAAPayloadBuilder();
        payloadBuilder.setSecureRandomProvider(seed -> new SecureRandom());

        SDJWTEAAService service = new SDJWTEAAService(new CommonCertificateVerifier());
        service.setPayloadBuilder(payloadBuilder);
        // end::sdjwt-custom-secure-random[]

        // tag::mdoc-custom-salt[]
        // For mdoc, provide an explicit salt (byte array) when creating a custom claim
        byte[] customSalt = new SecureRandom().generateSeed(16); // 128-bit random salt
        MdocEAAClaim mdocClaimWithSalt = MdocEAAClaim.create("org.iso.18013.5.1", "given_name", "John", customSalt);
        // end::mdoc-custom-salt[]

        // tag::mdoc-custom-secure-random[]
        // Replace the default deterministic SecureRandomProvider with a fully non-deterministic one
        MdocEAAPayloadBuilder mdocEAAPayloadBuilder = new MdocEAAPayloadBuilder();
        mdocEAAPayloadBuilder.setSecureRandomProvider(seed -> new SecureRandom());

        MdocEAAService mdocService = new MdocEAAService(new CommonCertificateVerifier());
        mdocService.setPayloadBuilder(mdocEAAPayloadBuilder);
        // end::mdoc-custom-secure-random[]


        DefaultEAAPresentationValidator validator = new MdocDeviceResponseEAAPresentationValidator();

        // tag::online-eaa-revocation-source[]
        // Default (uses NativeHTTPDataLoader)
        OnlineEAARevocationSource revocationSource = new OnlineEAARevocationSource();

        // Attach to the validator
        validator.setEAARevocationSource(revocationSource);
        // end::online-eaa-revocation-source[]

        // tag::external-eaa-revocation-source[]
        // import eu.europa.esig.dss.eaa.revocation.source.ExternalResourcesEAARevocationSource;

        ExternalResourcesEAARevocationSource externalRevocationSource = new ExternalResourcesEAARevocationSource("path/to/status-list-token.jwt");

        // Attach to the validator
        validator.setEAARevocationSource(revocationSource);
        // end::external-eaa-revocation-source[]

        // tag::eaa-validation-policy[]
        // import eu.europa.esig.dss.model.FileDocument;

        // Custom validation policy
        Reports reportsFromCustomPolicy = validator.validateDocument(new FileDocument("path/to/custom-eaa-policy.xml"));

        // Default validation policy
        Reports reports = validator.validateDocument();
        // end::eaa-validation-policy[]
    }
}

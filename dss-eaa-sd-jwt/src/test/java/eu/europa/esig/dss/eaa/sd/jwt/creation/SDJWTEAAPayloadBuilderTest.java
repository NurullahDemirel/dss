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

import eu.europa.esig.dss.eaa.common.creation.DefaultEAASaltGenerator;
import eu.europa.esig.dss.eaa.common.creation.EAASaltGenerator;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SDJWTEAAPayloadBuilderTest {

    @Test
    void buildSDJWTEAAPayload() throws JoseException {
        EAASaltGenerator saltGenerator = new DefaultEAASaltGenerator();
        final SDJWTEAAPayloadParameters parameters = new SDJWTEAAPayloadParameters();

        final SDJWTEAAClaimObject addressClaim = SDJWTEAAClaim.createObject("address");
        addressClaim.addChild(SDJWTEAAClaim.create("country", "LU"));
        addressClaim.addChild(SDJWTEAAClaim.create("street", "Test street"));
        addressClaim.addChild(SDJWTEAAClaim.createSelectivelyDisclosable("city", "Luxembourg"));
        addressClaim.addChild(SDJWTEAAClaim.createSelectivelyDisclosable("postal-code", "4000"));

        final SDJWTEAAClaimObject subObject = SDJWTEAAClaim.createObject("sub-addressClaim");
        subObject.addChild(SDJWTEAAClaim.create("sub-key", "sub-value"));
        subObject.addChild(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("sub-key-hidden", "sub-value-hidden", getSalt(saltGenerator)));
        addressClaim.addChild(subObject);

        final SDJWTEAAClaimArray pets = SDJWTEAAClaimArray.create("pets");
        pets.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("dog", getSalt(saltGenerator)));
        pets.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("cat", getSalt(saltGenerator)));
        addressClaim.addChild(pets);

        final SDJWTEAAClaimArray nationalities = SDJWTEAAClaimArray.create("nationalities");
        nationalities.addElement(SDJWTEAAClaim.create("DE"));
        nationalities.addElement(SDJWTEAAClaim.create("EN"));
        nationalities.addElement(SDJWTEAAClaim.create("FR"));
        nationalities.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("LU", getSalt(saltGenerator)));

        final SDJWTEAAClaimArray nationalities2 = SDJWTEAAClaimArray.createSelectivelyDisclosableWithSalt("nationalities2", getSalt(saltGenerator));
        nationalities2.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("DE", getSalt(saltGenerator)));
        nationalities2.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("EN", getSalt(saltGenerator)));
        nationalities2.addElement(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("FR", getSalt(saltGenerator)));

        parameters.nonSelectivelyDisclosable().addClaim(addressClaim);
        parameters.nonSelectivelyDisclosable().addClaim(nationalities);
        parameters.selectivelyDisclosable().addClaim(nationalities2);

        final SDJWTEAAClaim nonSdClaim = SDJWTEAAClaim.create("visible-claim", "visible-value");
        parameters.nonSelectivelyDisclosable().addClaim(nonSdClaim);

        final SDJWTEAAClaim sdClaim = SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("test-name", "test-value");
        parameters.selectivelyDisclosable().addClaim(sdClaim);

        final Date now = new Date();
        final Date expiration = new Date(now.getTime() + 3600 * 1000);
        parameters.setIssuanceDate(now);
        parameters.setExpirationDate(expiration);
        parameters.setSubject("test-subject");
        parameters.setIssuer("test-issuer");

        final Map<String, Object> map = parsePayload(parameters);

        assertEquals(9, map.size());
        assertEquals("test-issuer", map.get(SDJWTConstants.ISSUER));
        assertEquals("test-subject", map.get(SDJWTConstants.SUBJECT));
        assertEquals(DigestAlgorithm.SHA256.getSDJWTId(), map.get(SDJWTConstants._SD_ALG));
        assertEquals(now.toInstant().getEpochSecond(), map.get(SDJWTConstants.ISSUED_AT));
        assertEquals(expiration.toInstant().getEpochSecond(), map.get(SDJWTConstants.EXPIRATION_TIME));

        List<String> rootSd = (List<String>) map.get(SDJWTConstants._SD);
        assertEquals(2, rootSd.size());

        assertEquals("visible-value", map.get("visible-claim"));
        assertNull(map.get("test-name"));
        assertNull(map.get("nationalities2"));

        Map<String, Object> address = (Map<String, Object>) map.get("address");
        assertNotNull(address);
        assertEquals(5, address.size());
        assertEquals("LU", address.get("country"));
        assertEquals("Test street", address.get("street"));
        assertNull(address.get("city"));
        assertNull(address.get("postal-code"));
        List<String> addressSd = (List<String>) address.get(SDJWTConstants._SD);
        assertEquals(2, addressSd.size()); // city + postal-code

        Map<String, Object> subAddressClaim = (Map<String, Object>) address.get("sub-addressClaim");
        assertNotNull(subAddressClaim);
        assertEquals("sub-value", subAddressClaim.get("sub-key"));
        assertNull(subAddressClaim.get("sub-key-hidden"));
        List<String> subSd = (List<String>) subAddressClaim.get(SDJWTConstants._SD);
        assertEquals(1, subSd.size());

        List<Map<String, String>> petsArray = (List<Map<String, String>>) address.get("pets");
        assertEquals(2, petsArray.size());
        assertTrue(petsArray.stream().allMatch(e -> e.containsKey(SDJWTConstants.HASH)));

        List<Object> natArray = (List<Object>) map.get("nationalities");
        assertNotNull(natArray);
        assertEquals(4, natArray.size());
        assertEquals("DE", natArray.get(0));
        assertEquals("EN", natArray.get(1));
        assertEquals("FR", natArray.get(2));
        assertTrue(((Map<?, ?>) natArray.get(3)).containsKey(SDJWTConstants.HASH));

        List<SDJWTEAADisclosure> disclosures = new SDJWTEAAPayloadBuilder().buildDisclosures(parameters);
        assertEquals(11, disclosures.size());
    }

    private String getSalt(EAASaltGenerator saltGenerator) {
        return DSSJsonUtils.toBase64Url(saltGenerator.generateSalt());
    }

    @Test
    void onlyTechnicalClaims() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setIssuer("https://issuer.example.com");
        params.setSubject("user_42");
        Date now = new Date(1683000000000L);
        params.setIssuanceDate(now);
        params.setExpirationDate(new Date(now.getTime() + 3_600_000));

        Map<String, Object> map = parsePayload(params);

        assertEquals(DigestAlgorithm.SHA256.getSDJWTId(), map.get(SDJWTConstants._SD_ALG));
        assertEquals("https://issuer.example.com", map.get(SDJWTConstants.ISSUER));
        assertEquals("user_42", map.get(SDJWTConstants.SUBJECT));
        assertNotNull(map.get(SDJWTConstants.ISSUED_AT));
        assertNotNull(map.get(SDJWTConstants.EXPIRATION_TIME));

        assertNull(map.get(SDJWTConstants._SD));
        assertEquals(5, map.size()); // iss, sub, iat, exp, _sd_alg
    }

    @Test
    void nonSdClaimsAppearAsPlainFields() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.nonSelectivelyDisclosable().setFamilyName("Doe");
        params.nonSelectivelyDisclosable().setGivenName("John");

        Map<String, Object> map = parsePayload(params);

        assertEquals("Doe", map.get(SDJWTConstants.USER_FAMILY_NAME));
        assertEquals("John", map.get(SDJWTConstants.USER_GIVEN_NAME));
        assertNull(map.get(SDJWTConstants._SD));
    }

    @Test
    void sdClaimsAppearInSdArray() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.selectivelyDisclosable().setFamilyName("Doe");
        params.selectivelyDisclosable().setGivenName("John");

        Map<String, Object> map = parsePayload(params);

        // Claims must NOT appear as plain fields
        assertNull(map.get(SDJWTConstants.USER_FAMILY_NAME));
        assertNull(map.get(SDJWTConstants.USER_GIVEN_NAME));
        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);
        assertNotNull(sd);
        assertEquals(2, sd.size());
    }

    @Test
    void mixedSdAndNonSdClaims() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.nonSelectivelyDisclosable().setFamilyName("Doe");
        params.selectivelyDisclosable().setGivenName("John");

        Map<String, Object> map = parsePayload(params);

        assertEquals("Doe", map.get(SDJWTConstants.USER_FAMILY_NAME));
        assertNull(map.get(SDJWTConstants.USER_GIVEN_NAME));
        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);
        assertNotNull(sd);
        assertEquals(1, sd.size());
    }

    @Test
    void defaultDigestAlgorithm() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();

        Map<String, Object> map = parsePayload(params);

        assertEquals(DigestAlgorithm.SHA256.getSDJWTId(), map.get(SDJWTConstants._SD_ALG));
    }

    @Test
    void changeDefaultDigestAlgorithm() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setDigestAlgorithm(DigestAlgorithm.SHA512);
        params.selectivelyDisclosable().setFamilyName("Doe");

        Map<String, Object> map = parsePayload(params);

        assertEquals(DigestAlgorithm.SHA512.getSDJWTId(), map.get(SDJWTConstants._SD_ALG));
    }

    @Test
    void nonSelectivelyDisclosableObject() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.nonSelectivelyDisclosable().setAddressStreet("123 Main St");
        params.nonSelectivelyDisclosable().setAddressCity("Anytown");
        params.nonSelectivelyDisclosable().setAddressCountry("LU");

        Map<String, Object> map = parsePayload(params);

        assertNull(map.get(SDJWTConstants._SD));
        Map<String, Object> address = (Map<String, Object>) map.get(SDJWTConstants.USER_ADDRESS);
        assertNotNull(address);
        assertEquals("123 Main St", address.get(SDJWTConstants.USER_ADDRESS_STREET_ADDRESS));
        assertEquals("Anytown", address.get(SDJWTConstants.USER_ADDRESS_LOCALITY));
        assertEquals("LU", address.get(SDJWTConstants.USER_ADDRESS_COUNTRY));
    }

    @Test
    void selectivelyDisclosableObject() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.selectivelyDisclosable().setAddressStreet("123 Main St");
        params.selectivelyDisclosable().setAddressCity("Anytown");
        params.selectivelyDisclosable().setAddressCountry("LU");

        Map<String, Object> map = parsePayload(params);

        assertNull(map.get(SDJWTConstants.USER_ADDRESS));
        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);
        assertNotNull(sd);
        assertEquals(1, sd.size());
    }

    @Test
    void arrayWithSelectivelyDisclosableElements() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        SDJWTEAAClaimArray nationalities = SDJWTEAAClaimArray.create("nationalities");
        nationalities.addElement(SDJWTEAAClaim.create("LU"));
        nationalities.addElement(SDJWTEAAClaim.createSelectivelyDisclosable("DE"));
        params.nonSelectivelyDisclosable().addClaim(nationalities);

        Map<String, Object> map = parsePayload(params);

        assertNull(map.get(SDJWTConstants._SD));
        List<Object> nat = (List<Object>) map.get("nationalities");
        assertNotNull(nat);
        assertEquals(2, nat.size());
        assertEquals("LU", nat.get(0));
        Map<String, String> hashedElement = (Map<String, String>) nat.get(1);
        assertTrue(hashedElement.containsKey(SDJWTConstants.HASH));
    }

    @Test
    void rawMapValueConvertedToJsonObject() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        Map<String, Object> rawMap = new LinkedHashMap<>();
        rawMap.put("key1", "val1");
        rawMap.put("key2", 42);
        params.nonSelectivelyDisclosable().addClaim(SDJWTEAAClaim.create("nested", rawMap));

        Map<String, Object> map = parsePayload(params);

        Map<String, Object> nested = (Map<String, Object>) map.get("nested");
        assertNotNull(nested);
        assertEquals("val1", nested.get("key1"));
        assertEquals(42L, nested.get("key2")); // JSON numbers come back as Long
    }

    @Test
    void rawListValueConvertedToJsonArray() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.nonSelectivelyDisclosable().addClaim(SDJWTEAAClaim.create("items", Arrays.asList("a", "b", "c")));

        Map<String, Object> map = parsePayload(params);

        List<String> items = (List<String>) map.get("items");
        assertNotNull(items);
        assertEquals(Arrays.asList("a", "b", "c"), items);
    }

    @Test
    void decoyDigestAdded() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.selectivelyDisclosable().setFamilyName("Doe");
        params.setDecoyDigestNumber(3);

        Map<String, Object> map = parsePayload(params);

        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);
        assertEquals(4, sd.size()); // 1 claim + 3 decoys
    }

    @Test
    void decoyDigestLengthMatchesSha256OutputLength() throws JoseException {
        assertDecoyBase64UrlLength(DigestAlgorithm.SHA256, 43);
    }

    @Test
    void decoyDigestLengthMatchesSha384OutputLength() throws JoseException {
        assertDecoyBase64UrlLength(DigestAlgorithm.SHA384, 64);
    }

    @Test
    void decoyDigestLengthMatchesSha512OutputLength() throws JoseException {
        assertDecoyBase64UrlLength(DigestAlgorithm.SHA512, 86);
    }

    @Test
    void onlyDecoyDigests() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setDecoyDigestNumber(3);

        Map<String, Object> map = parsePayload(params);

        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);
        assertNotNull(sd);
        assertEquals(3, sd.size());
    }

    @Test
    void sameParamsProduceDeterministicPayload() {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setIssuer("https://issuer.example.com");
        params.setIssuanceDate(new Date());
        params.selectivelyDisclosable().setFamilyName("Doe");
        params.selectivelyDisclosable().setGivenName("John");

        SDJWTEAAPayloadBuilder builder = new SDJWTEAAPayloadBuilder();
        byte[] first  = ((InMemoryDocument) builder.buildPayload(params)).getBytes();
        byte[] second = ((InMemoryDocument) builder.buildPayload(params)).getBytes();

        assertArrayEquals(first, second);
    }

    @Test
    void differentParamsProduceDifferentPayload() {
        Date now = new Date();

        SDJWTEAAPayloadParameters params1 = new SDJWTEAAPayloadParameters();
        params1.setIssuer("https://issuer-a.example.com");
        params1.setIssuanceDate(now);
        params1.selectivelyDisclosable().setFamilyName("Doe");

        SDJWTEAAPayloadParameters params2 = new SDJWTEAAPayloadParameters();
        params2.setIssuer("https://issuer-b.example.com"); // different issuer → different seed
        params2.setIssuanceDate(now);
        params2.selectivelyDisclosable().setFamilyName("Doe");

        SDJWTEAAPayloadBuilder builder = new SDJWTEAAPayloadBuilder();
        byte[] payload1 = ((InMemoryDocument) builder.buildPayload(params1)).getBytes();
        byte[] payload2 = ((InMemoryDocument) builder.buildPayload(params2)).getBytes();

        assertFalse(Arrays.equals(payload1, payload2));
    }

    @Test
    void shuffleDisabledHashOrder() throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setShuffleHashes(false);
        params.setDecoyDigestNumber(1);

        // 1 SD claim with a fixed salt → fully deterministic hash
        String fixedSalt = "fixed-salt-for-test";
        params.selectivelyDisclosable().addClaim(SDJWTEAAClaim.createSelectivelyDisclosableWithSalt("claim-name", "claim-value", fixedSalt));

        SDJWTEAADisclosure expectedDisclosure = new DefaultSDJWTDisclosureBuilder()
                .build("claim-name", "claim-value", fixedSalt);
        String expectedHash = DSSJsonUtils.toBase64Url(
                expectedDisclosure.computeDigest(DigestAlgorithm.SHA256).getValue());

        Map<String, Object> map = parsePayload(params);
        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);

        assertNotNull(sd);
        assertEquals(2, sd.size()); // 1 real + 1 decoy
        // With shuffle disabled, the 'real' hash must come first, decoy last
        assertEquals(expectedHash, sd.get(0));
        assertNotEquals(expectedHash, sd.get(1));
    }

    private Map<String, Object> parsePayload(SDJWTEAAPayloadParameters params) throws JoseException {
        InMemoryDocument payload = (InMemoryDocument) new SDJWTEAAPayloadBuilder().buildPayload(params);
        return JsonUtil.parseJson(new String(payload.getBytes()));
    }

    private void assertDecoyBase64UrlLength(DigestAlgorithm algo, int expectedLength) throws JoseException {
        SDJWTEAAPayloadParameters params = new SDJWTEAAPayloadParameters();
        params.setDigestAlgorithm(algo);
        params.setDecoyDigestNumber(3); // no real SD claims, all entries are decoys

        Map<String, Object> map = parsePayload(params);
        List<String> sd = (List<String>) map.get(SDJWTConstants._SD);

        assertNotNull(sd);
        for (String decoy : sd) {
            assertEquals(expectedLength, decoy.length(),
                    "Decoy digest length for " + algo + " should be " + expectedLength + " chars");
        }
    }

}

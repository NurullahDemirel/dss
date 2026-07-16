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

import eu.europa.esig.dss.eaa.common.creation.AbstractEAAPayloadBuilder;
import eu.europa.esig.dss.eaa.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.jades.DSSJsonUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.jose4j.json.JsonUtil;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Creates a payload for an RFC 9901 SD-JWT VC token based on the provided parameters
 *
 */
public class SDJWTEAAPayloadBuilder extends AbstractEAAPayloadBuilder<SDJWTEAAPayloadParameters, SDJWTEAADisclosure> {

    /** Builds disclosures */
    private SDJWTDisclosureBuilder disclosureBuilder = new DefaultSDJWTDisclosureBuilder();

    /** Builds known and custom claims */
    private SDJWTEAAClaimBuilder claimBuilder = new DefaultSDJWTEAAClaimBuilder();

    /**
     * Default constructor
     */
    public SDJWTEAAPayloadBuilder() {
        // empty
    }

    /**
     * Sets a disclosure builder.
     * Default : {@code eu.europa.esig.dss.eaa.jwt.creation.DefaultSDJWTDisclosureBuilder}
     *
     * @param disclosureBuilder {@link SDJWTDisclosureBuilder}
     */
    public void setDisclosureBuilder(SDJWTDisclosureBuilder disclosureBuilder) {
        Objects.requireNonNull(disclosureBuilder, "Disclosure builder cannot be null!");
        this.disclosureBuilder = disclosureBuilder;
    }

    /**
     * Gets a configured instance of {@code SDJWTEAAClaimBuilder}
     *
     * @return {@link SDJWTEAAClaimBuilder}
     */
    protected SDJWTEAAClaimBuilder getClaimBuilder() {
        claimBuilder.setPublicKeyInfoFactory(getPublicKeyInfoFactory());
        return claimBuilder;
    }

    /**
     * Sets a claim builder.
     * Default : {@code eu.europa.esig.dss.eaa.jwt.creation.DefaultSDJWTEAAClaimBuilder}
     *
     * @param claimBuilder {@link SDJWTEAAClaimBuilder}
     */
    public void setClaimBuilder(final SDJWTEAAClaimBuilder claimBuilder) {
        Objects.requireNonNull(claimBuilder, "Claim builder cannot be null!");
        this.claimBuilder = claimBuilder;
    }

    @Override
    public DSSDocument buildPayload(SDJWTEAAPayloadParameters payloadParameters) {
        final Map<String, Object> map = new LinkedHashMap<>();

        DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;
        if (payloadParameters.getDigestAlgorithm() != null) {
            map.put(SDJWTConstants._SD_ALG, digestAlgorithm.getSDJWTId());
        }

        final SecureRandom secureRandom = secureRandom(payloadParameters);
        final SDJWTEAAClaimObject payload = getRootPayloadObject(payloadParameters, secureRandom);
        map.putAll(getEAAClaimObjectValue(new DisclosureTraversalContext(), payload, digestAlgorithm, secureRandom, payloadParameters.isShuffleHashes()));

        return new InMemoryDocument(JsonUtil.toJson(map).getBytes());
    }

    private SDJWTEAAClaimObject getRootPayloadObject(SDJWTEAAPayloadParameters payloadParameters, SecureRandom secureRandom) {
        final SDJWTEAAClaimObject payload = SDJWTEAAClaimObject.create();

        payload.addChildren(getClaimBuilder().buildClaims(payloadParameters));

        if (payloadParameters.getDecoyDigestNumber() > 0) {
            DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                    payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;
            int digestLength = digestAlgorithm.getSaltLength();
            for (int i = 0; i < payloadParameters.getDecoyDigestNumber(); i++) {
                byte[] bytes = secureRandom.generateSeed(digestLength);
                payload.addDecoyDigest(DSSJsonUtils.toBase64Url(bytes));
            }
        }

        return payload;
    }

    private Object getClaimValue(final DisclosureTraversalContext dtx, final SDJWTEAAClaim claim, final DigestAlgorithm digestAlgorithm, final SecureRandom secureRandom, final boolean shuffleHashes) {
        if (claim instanceof SDJWTEAAClaimObject) {
            return getEAAClaimObjectValue(dtx, (SDJWTEAAClaimObject) claim, digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim instanceof SDJWTEAAClaimArray) {
            return getEAAClaimArrayValue(dtx, (SDJWTEAAClaimArray) claim, digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Map) {
            return getClaimValue(dtx, toEAAClaimObject((Map<?, ?>) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Collection) {
            return getClaimValue(dtx, toEAAClaimArray((Collection<?>) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);

        } else if (claim.getValue() instanceof Object[]) {
            return getClaimValue(dtx, toEAAClaimArray((Object[]) claim.getValue()), digestAlgorithm, secureRandom, shuffleHashes);
        }

        return claim.getValue();
    }

    private SDJWTEAAClaimObject toEAAClaimObject(Map<?, ?> map) {
        final SDJWTEAAClaimObject result = SDJWTEAAClaimObject.create();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!(entry.getKey() instanceof String)) {
                throw new DSSException("Map key must be String");
            }

            String name = (String) entry.getKey();
            Object value = entry.getValue();

            if (value instanceof SDJWTEAAClaim) {
                result.addChild((SDJWTEAAClaim) value);
            } else {
                result.addChild(SDJWTEAAClaim.create(name, value));
            }
        }
        return result;
    }

    private SDJWTEAAClaimArray toEAAClaimArray(Object[] array) {
        final SDJWTEAAClaimArray result = SDJWTEAAClaimArray.create();
        for (Object item : array) {
            if (item instanceof SDJWTEAAClaim) {
                result.addElement((SDJWTEAAClaim) item);
            } else {
                result.addElement(SDJWTEAAClaim.create(item));
            }
        }
        return result;
    }

    private SDJWTEAAClaimArray toEAAClaimArray(Collection<?> collection) {
        final SDJWTEAAClaimArray result = SDJWTEAAClaimArray.create();
        for (Object item : collection) {
            if (item instanceof SDJWTEAAClaim) {
                result.addElement((SDJWTEAAClaim) item);
            } else {
                result.addElement(SDJWTEAAClaim.create(item));
            }
        }
        return result;
    }

    private Map<String, Object> getEAAClaimObjectValue(final DisclosureTraversalContext dtx, final SDJWTEAAClaimObject objectClaim,
                                                       final DigestAlgorithm digestAlgorithm, final SecureRandom secureRandom,
                                                       final boolean shuffleHashes) {
        Map<String, Object> result = new LinkedHashMap<>();
        List<String> selectivelyDisclosableClaims = new ArrayList<>();

        objectClaim.getChildren().forEach(child -> {
            if (child.isSelectivelyDisclosable()) {
                selectivelyDisclosableClaims.add(getHashedDisclosure(dtx, child, digestAlgorithm, secureRandom, shuffleHashes));
            } else {
                result.put(child.getName(), getClaimValue(dtx, child, digestAlgorithm, secureRandom, shuffleHashes));
            }
        });

        selectivelyDisclosableClaims.addAll(objectClaim.getDecoyDigests());
        if (!selectivelyDisclosableClaims.isEmpty()) {
            if (shuffleHashes) {
                Collections.shuffle(selectivelyDisclosableClaims, secureRandom);
            }
            result.put(SDJWTConstants._SD, selectivelyDisclosableClaims);
        }

        return result;
    }

    private List<Object> getEAAClaimArrayValue(final DisclosureTraversalContext dtx, final SDJWTEAAClaimArray arrayClaim,
                                               final DigestAlgorithm digestAlgorithm, SecureRandom secureRandom,
                                               final boolean shuffleHashes) {
        List<Object> result = new ArrayList<>();
        List<Object> hashedElements = new ArrayList<>();

        arrayClaim.getElements().forEach(element -> {
            if (element.isSelectivelyDisclosable()) {
                Map<String, String> hashedElement = new LinkedHashMap<>();
                hashedElement.put(SDJWTConstants.HASH, getHashedDisclosure(dtx, element, digestAlgorithm, secureRandom, shuffleHashes));
                hashedElements.add(hashedElement);
            } else {
                result.add(getClaimValue(dtx, element, digestAlgorithm, secureRandom, shuffleHashes));
            }
        });

        arrayClaim.getDecoyDigests().forEach(decoyDigest -> {
            Map<String, String> decoyElement = new LinkedHashMap<>();
            decoyElement.put(SDJWTConstants.HASH, decoyDigest);
            hashedElements.add(decoyElement);
        });

        if (shuffleHashes) {
            Collections.shuffle(hashedElements, secureRandom);
        }
        result.addAll(hashedElements);

        return result;
    }

    private String getHashedDisclosure(DisclosureTraversalContext dtx, SDJWTEAAClaim claim, DigestAlgorithm digestAlgorithm, SecureRandom secureRandom, boolean shuffleHashes) {
        return dtx.getHash(claim, () -> {
            SDJWTEAADisclosure disclosure = getDisclosure(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes);
            Digest digest = disclosure.computeDigest(digestAlgorithm);
            return DSSJsonUtils.toBase64Url(digest.getValue());
        });
    }

    private SDJWTEAADisclosure getDisclosure(DisclosureTraversalContext dtx, SDJWTEAAClaim claim, DigestAlgorithm digestAlgorithm,
                                             SecureRandom secureRandom, boolean shuffleHashes) {
        return dtx.getDisclosure(claim, () -> buildDisclosure(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes));
    }

    /**
     * Build the disclosure for the given claim
     *
     * @param dtx {@link DisclosureTraversalContext}
     * @param claim the claim
     * @param digestAlgorithm the digest algorithm
     * @param secureRandom {@link SecureRandom}
     * @param shuffleHashes if the hashes should be shuffled
     * @return {@link SDJWTEAADisclosure}
     */
    protected SDJWTEAADisclosure buildDisclosure(DisclosureTraversalContext dtx, SDJWTEAAClaim claim, DigestAlgorithm digestAlgorithm, SecureRandom secureRandom, boolean shuffleHashes) {
        Object claimValue = getClaimValue(dtx, claim, digestAlgorithm, secureRandom, shuffleHashes);
        String salt = claim.getSalt();
        if (Utils.isStringEmpty(salt)) {
            byte[] bytes = nextRandomSalt(secureRandom); // 16 * 8 = 128 bits
            salt = DSSJsonUtils.toBase64Url(bytes);
        }
        return disclosureBuilder.build(claim.getName(), claimValue, salt);
    }

    @Override
    public List<SDJWTEAADisclosure> buildDisclosures(SDJWTEAAPayloadParameters payloadParameters) {
        DigestAlgorithm digestAlgorithm = payloadParameters.getDigestAlgorithm() != null ?
                payloadParameters.getDigestAlgorithm() : DigestAlgorithm.SHA256;

        SecureRandom secureRandom = secureRandom(payloadParameters);
        SDJWTEAAClaimObject root = getRootPayloadObject(payloadParameters, secureRandom);
        return collectDisclosures(root, digestAlgorithm, secureRandom, payloadParameters.isShuffleHashes());
    }

    private List<SDJWTEAADisclosure> collectDisclosures(final SDJWTEAAClaimObject root, final DigestAlgorithm digestAlgorithm,
                                                        final SecureRandom secureRandom, final boolean shuffleHashes) {
        DisclosureTraversalContext dtx = new DisclosureTraversalContext();
        getEAAClaimObjectValue(dtx, root, digestAlgorithm, secureRandom, shuffleHashes);
        return dtx.getDisclosures();
    }

    /**
     * Holds traversal state while generating an SD-JWT payload and its
     * associated disclosures.
     * <p>
     * This context ensures that disclosures and their corresponding hashes
     * are generated only once per claim instance and subsequently reused.
     * This guarantees deterministic disclosure generation for nested
     * selectively-disclosable claims and prevents inconsistencies caused by
     * recomputing disclosures with different salts.
     */
    private static class DisclosureTraversalContext {

        /**
         * Cache of generated disclosures keyed by claim instance.
         * <p>
         * An {@link IdentityHashMap} is used to ensure caching is based on
         * object identity rather than {@code equals}/{@code hashCode}.
         */
        private final Map<SDJWTEAAClaim, SDJWTEAADisclosure> disclosuresMap = new IdentityHashMap<>();

        /**
         * Cache of disclosure hashes keyed by claim instance.
         * <p>
         * This guarantees that a disclosure hash is computed only once and
         * reused whenever referenced by parent disclosures.
         */
        private final Map<SDJWTEAAClaim, String> hashesMap = new IdentityHashMap<>();

        /**
         * Ordered list of generated disclosures.
         * <p>
         * The order reflects the first encounter of disclosures during claim
         * tree traversal and is used to produce deterministic output.
         */
        private final List<SDJWTEAADisclosure> disclosuresList = new ArrayList<>();

        /**
         * Returns the disclosure associated with the given claim.
         * <p>
         * If no disclosure has been generated yet, the supplied function is
         * invoked to create and cache it. Newly created disclosures are also
         * recorded in the ordered disclosure list.
         *
         * @param claim {@link SDJWTEAAClaim} for which a disclosure is requested
         * @param supplier supplies a disclosure when one is not yet cached
         * @return the cached or newly created disclosure
         */
        public SDJWTEAADisclosure getDisclosure(SDJWTEAAClaim claim, Supplier<SDJWTEAADisclosure> supplier) {
            return disclosuresMap.computeIfAbsent(claim, c -> {
                SDJWTEAADisclosure disclosure = supplier.get();
                disclosuresList.add(disclosure);
                return disclosure;
            });
        }

        /**
         * Returns the disclosure hash associated with the given claim.
         * <p>
         * If the hash has not yet been computed, the supplied function is
         * invoked and the resulting value is cached.
         *
         * @param claim {@link SDJWTEAAClaim} for which a disclosure hash is requested
         * @param supplier supplies a hash when one is not yet cached
         * @return the cached or newly computed disclosure hash
         */
        public String getHash(SDJWTEAAClaim claim, Supplier<String> supplier) {
            return hashesMap.computeIfAbsent(claim, k -> supplier.get());
        }

        /**
         * Returns the disclosures generated during traversal in deterministic
         * encounter order.
         *
         * @return a list of {@link SDJWTEAADisclosure}s
         */
        public List<SDJWTEAADisclosure> getDisclosures() {
            return disclosuresList;
        }

    }

}

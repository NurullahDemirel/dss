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
package eu.europa.esig.dss.eaa.jwt.creation;

import eu.europa.esig.dss.eaa.common.creation.claim.EAAClaimObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Represents a JSON object to be incorporated as an SD-JWT VC claim
 *
 */
public class SDJWTEAAClaimObject extends SDJWTEAAClaim implements EAAClaimObject<SDJWTEAAClaim> {

    private static final long serialVersionUID = 3602569321684484970L;

    /** Decoy digests used to hide the number of selectively disclosable items */
    private final List<String> decoyDigests = new ArrayList<>();

    /**
     * Create a {@link SDJWTEAAClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject create() {
        return new SDJWTEAAClaimObject(null, false);
    }

    /**
     * Create a {@link SDJWTEAAClaim} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject create(final String name) {
        return new SDJWTEAAClaimObject(name, false);
    }

    /**
     * Create a selectively disclosable {@link SDJWTEAAClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject createSelectivelyDisclosable() {
        return new SDJWTEAAClaimObject(null, true);
    }

    /**
     * Create a selectively disclosable {@link SDJWTEAAClaimObject} with the provided salt. The name of the claim will be null.
     *
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject createSelectivelyDisclosableWithSalt(final String salt) {
        return new SDJWTEAAClaimObject(null, true, salt);
    }

    /**
     * Create a selectively disclosable {@link SDJWTEAAClaim} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject createSelectivelyDisclosable(final String name) {
        return new SDJWTEAAClaimObject(name, true);
    }

    /**
     * Create a selectively disclosable {@link SDJWTEAAClaim} with the provided name and salt
     *
     * @param name {@link String} the name of the claim
     * @param salt {@link String} the salt value
     * @return the created {@link SDJWTEAAClaim}
     */
    public static SDJWTEAAClaimObject createSelectivelyDisclosableWithSalt(final String name, final String salt) {
        return new SDJWTEAAClaimObject(name, true, salt);
    }

    /**
     * Constructor with the claim name and selectively disclosable status.
     * When the selectivelyDisclosable status is enabled but no salt is provided,
     * the salt will be generated during the EAA Payload computation.
     *
     * @param name  {@link String} the claim name
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     */
    protected SDJWTEAAClaimObject(final String name, final boolean selectivelyDisclosable) {
        super(name, new ArrayList<SDJWTEAAClaim>(), selectivelyDisclosable, null);
    }

    /**
     * Constructor with the claim name, selectively disclosable status and salt provided
     *
     * @param name  {@link String} the claim name
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     * @param salt {@link String} the salt (mandatory if the claim is selectively disclosable)
     */
    protected SDJWTEAAClaimObject(final String name, final boolean selectivelyDisclosable, final String salt) {
        super(name, new ArrayList<SDJWTEAAClaim>(), selectivelyDisclosable, salt);
    }

    /**
     * Constructor with the claim name, value, selectively disclosable status and salt provided
     *
     * @param name  {@link String} the claim name
     * @param children a list of children
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     * @param salt {@link String} the salt (mandatory if the claim is selectively disclosable)
     */
    protected SDJWTEAAClaimObject(final String name, List<SDJWTEAAClaim> children, final boolean selectivelyDisclosable, final String salt) {
        super(name, children, selectivelyDisclosable, salt);
    }

    @Override
    public void addChild(final SDJWTEAAClaim child) {
        getChildren().add(child);
    }

    /**
     * Adds a collection of children to the object
     *
     * @param children a collection of {@link SDJWTEAAClaim}
     */
    public void addChildren(final Collection<SDJWTEAAClaim> children) {
        getChildren().addAll(children);
    }

    @Override
    public List<SDJWTEAAClaim> getChildren() {
        return (List<SDJWTEAAClaim>) getValue();
    }

    /**
     * Adds a decoy digest to the claim.
     *
     * @param digest the decoy digest to add
     */
    public void addDecoyDigest(String digest) {
        decoyDigests.add(digest);
    }

    /**
     * Gets the decoy digests of this claim
     *
     * @return The list of decoy digests
     */
    public List<String> getDecoyDigests() {
        return Collections.unmodifiableList(decoyDigests);
    }

}

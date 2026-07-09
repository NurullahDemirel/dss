package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.eaa.common.creation.claim.EAAClaimObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Represents a CBOR object to be incorporated as an ISO/IEC mdoc claim
 *
 */
public class MdocEAAClaimObject extends MdocEAAClaim implements EAAClaimObject<MdocEAAClaim> {

    private static final long serialVersionUID = 3168092769419251983L;

    /**
     * Create a {@link MdocEAAClaimObject}. The name of the claim will be null.
     *
     * @return the created {@link MdocEAAClaimObject}
     */
    public static MdocEAAClaimObject create() {
        return new MdocEAAClaimObject(new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimObject} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link MdocEAAClaimObject}
     */
    public static MdocEAAClaimObject create(final String name) {
        return new MdocEAAClaimObject(name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimObject}.
     * DigestId and salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimObject create(final String namespace, final String name) {
        return new MdocEAAClaimObject(namespace, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimObject} with the provided digestId.
     * Salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimObject create(final String namespace, final int digestId, final String name) {
        return new MdocEAAClaimObject(namespace, digestId, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimObject} with the provided salt.
     * DigestId will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimObject create(final String namespace, final String name, final byte[] salt) {
        return new MdocEAAClaimObject(namespace, name, new ArrayList<>(), salt);
    }

    /**
     * Create a {@link MdocEAAClaimObject} with the provided digestId and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimObject create(final String namespace, final int digestId, final String name, final byte[] salt) {
        return new MdocEAAClaimObject(namespace, digestId, name, new ArrayList<>(), salt);
    }

    /**
     * Constructor with the value
     *
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     */
    protected MdocEAAClaimObject(List<MdocEAAClaim> children) {
        super(null, children);
    }

    /**
     * Constructor with the claim name and value
     *
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     */
    protected MdocEAAClaimObject(String name, List<MdocEAAClaim> children) {
        super(null, name, children);
    }

    /**
     * Constructor with the claim namespace, name and value
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     */
    protected MdocEAAClaimObject(String namespace, String name, List<MdocEAAClaim> children) {
        super(namespace, name, children);
    }

    /**
     * Constructor with the claim namespace, digestId, name and value
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     */
    protected MdocEAAClaimObject(String namespace, int digestId, String name, List<MdocEAAClaim> children) {
        super(namespace, digestId, name, children);
    }

    /**
     * Constructor with the claim namespace, name, value and salt
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocEAAClaimObject(String namespace, String name, List<MdocEAAClaim> children, byte[] salt) {
        super(namespace, name, children, salt);
    }

    /**
     * Constructor with the claim namespace, digestId, name, value and salt
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param children a list of embedded {@code MdocEAAClaim} in the object
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocEAAClaimObject(String namespace, int digestId, String name, List<MdocEAAClaim> children, byte[] salt) {
        super(namespace, digestId, name, children, salt);
    }

    @Override
    public void addChild(final MdocEAAClaim child) {
        getChildren().add(child);
    }

    /**
     * Adds a collection of children to the object
     *
     * @param children a collection of {@link MdocEAAClaim}
     */
    public void addChildren(final Collection<MdocEAAClaim> children) {
        getChildren().addAll(children);
    }

    @Override
    public List<MdocEAAClaim> getChildren() {
        return (List<MdocEAAClaim>) getValue();
    }

    @Override
    public CBORObject getValueAsCbor() {
        final CBORMap cborMap = new CBORMap();
        for (MdocEAAClaim child : getChildren()) {
            cborMap.put(child.getName(), child.getValueAsCbor());
        }
        return cborMap;
    }

}

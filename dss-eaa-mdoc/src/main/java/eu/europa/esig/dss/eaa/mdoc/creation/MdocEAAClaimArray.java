package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.eaa.common.creation.claim.EAAClaimArray;
import eu.europa.esig.dss.eaa.mdoc.creation.claim.MdocEAAClaim;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a CBOR array to be incorporated as an ISO/IEC mdoc claim
 *
 */
public class MdocEAAClaimArray extends MdocEAAClaim implements EAAClaimArray<MdocEAAClaim> {

    private static final long serialVersionUID = -8747676551662684772L;

    /**
     * Create a {@link MdocEAAClaimArray}. The name of the claim will be null.
     *
     * @return the created {@link MdocEAAClaimArray}
     */
    public static MdocEAAClaimArray create() {
        return new MdocEAAClaimArray(new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimArray} with the provided name
     *
     * @param name {@link String} the name of the claim
     * @return the created {@link MdocEAAClaimArray}
     */
    public static MdocEAAClaimArray create(final String name) {
        return new MdocEAAClaimArray(name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimArray}.
     * DigestId and salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimArray create(final String namespace, final String name) {
        return new MdocEAAClaimArray(namespace, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimArray} with the provided digestId.
     * Salt will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimArray create(final String namespace, final int digestId, final String name) {
        return new MdocEAAClaimArray(namespace, digestId, name, new ArrayList<>());
    }

    /**
     * Create a {@link MdocEAAClaimArray} with the provided salt.
     * DigestId will be computed during the payload generation process.
     *
     * @param namespace {@link String} the claim namespace
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimArray create(final String namespace, final String name, final byte[] salt) {
        return new MdocEAAClaimArray(namespace, name, new ArrayList<>(), salt);
    }

    /**
     * Create a {@link MdocEAAClaimArray} with the provided digestId and salt.
     *
     * @param namespace {@link String} the claim namespace
     * @param digestId integer identifier of the claim digest
     * @param name {@link String} the claim name
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     * @return the created {@link MdocEAAClaim}
     */
    public static MdocEAAClaimArray create(final String namespace, final int digestId, final String name, final byte[] salt) {
        return new MdocEAAClaimArray(namespace, digestId, name, new ArrayList<>(), salt);
    }

    /**
     * Constructor with the claim value
     *
     * @param value {@link List} value
     */
    protected MdocEAAClaimArray(List<?> value) {
        super(null, value);
    }

    /**
     * Constructor with the claim name and value
     *
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocEAAClaimArray(String name, List<?> value) {
        super(null, name, value);
    }

    /**
     * Constructor with the claim namespace, name and value
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocEAAClaimArray(String namespace, String name, List<?> value) {
        super(namespace, name, value);
    }

    /**
     * Constructor with the claim namespace, digestId, name and value
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     */
    protected MdocEAAClaimArray(String namespace, int digestId, String name, List<?> value) {
        super(namespace, digestId, name, value);
    }

    /**
     * Constructor with the claim namespace, name, value and salt
     *
     * @param namespace {@link String}
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocEAAClaimArray(String namespace, String name, List<?> value, byte[] salt) {
        super(namespace, name, value, salt);
    }

    /**
     * Constructor with the claim namespace, digestId, name, value and salt
     *
     * @param namespace {@link String}
     * @param digestId integer identifier of the claim digest
     * @param name  {@link String} the claim name
     * @param value {@link List} value
     * @param salt byte array containing a salt with a high entropy used for a digest computation
     */
    protected MdocEAAClaimArray(String namespace, int digestId, String name, List<?> value, byte[] salt) {
        super(namespace, digestId, name, value, salt);
    }

    @Override
    public void addElement(final MdocEAAClaim element) {
        getElements().add(element);
    }

    @Override
    public List<MdocEAAClaim> getElements() {
        return (List<MdocEAAClaim>) getValue();
    }

    @Override
    public CBORObject getValueAsCbor() {
        final CBORArray cborArray = new CBORArray();
        for (MdocEAAClaim element : getElements()) {
            cborArray.add(element.getValueAsCbor());
        }
        return cborArray;
    }

}

package eu.europa.esig.dss.eaa.mdoc.creation;

import eu.europa.esig.dss.cbades.signature.CBAdESSignatureParameters;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EAAPayloadProxy;
import eu.europa.esig.dss.diagnostic.EAAWrapper;
import eu.europa.esig.dss.diagnostic.claim.ClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegeClaimWrapper;
import eu.europa.esig.dss.diagnostic.claim.DrivingPrivilegesClaimWrapper;
import eu.europa.esig.dss.eaa.mdoc.ISO180135Headers;
import eu.europa.esig.dss.eaa.mdoc.MdocConstants;
import eu.europa.esig.dss.eaa.mdoc.model.MdocDrivingPrivilege;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MdocEAAISOMdLInvalidDrivingPrivilegeTest extends AbstractMdocEAAPresentationTestIssuance {

    private MdocEAAPayloadParameters payloadParameters;
    private CBAdESSignatureParameters signatureParameters;

    @BeforeEach
    void init() {
        payloadParameters = new MdocEAAPayloadParameters();
        payloadParameters.setDocType(MdocConstants.ISO18013_5_MDL_DOC_TYPE);
        payloadParameters.setDeviceKey(getSigningCert());

        MdocEAAClaimArray drivingPrivileges = MdocEAAClaim.createArray(MdocConstants.ISO18013_5_NAMESPACE, ISO180135Headers.DRIVING_PRIVILEGES);

        MdocEAAClaimObject drivingPrivilegeValid = MdocEAAClaim.createObject();
        drivingPrivilegeValid.addChild(MdocEAAClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE, "B"));
        drivingPrivilegeValid.addChild(MdocEAAClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_ISSUE_DATE, DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1)));
        drivingPrivilegeValid.addChild(MdocEAAClaim.create(ISO180135Headers.DRIVING_PRIVILEGES_EXPIRY_DATE, DSSUtils.getUtcDate(2020, Calendar.JANUARY, 1)));
        drivingPrivileges.addElement(drivingPrivilegeValid);

        drivingPrivileges.addElement(MdocEAAClaim.create("A"));

        payloadParameters.selectivelyDisclosable().addClaim(drivingPrivileges);

        signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
    }

    @Override
    protected void checkClaims(DiagnosticData diagnosticData) {
        super.checkClaims(diagnosticData);

        EAAWrapper eaa = diagnosticData.getEAAById(diagnosticData.getFirstEAAId());
        EAAPayloadProxy eaaPayload = eaa.getEAAPayload();

        DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper = eaaPayload.getDrivingPrivileges();
        assertNotNull(drivingPrivilegesClaimWrapper);

        List<DrivingPrivilegeClaimWrapper> drivingPrivileges = drivingPrivilegesClaimWrapper.getDrivingPrivileges();
        assertEquals(1, drivingPrivileges.size());
        assertEquals("B", drivingPrivileges.get(0).getVehicleCategoryCode().getText());

        List<ClaimWrapper> list = drivingPrivilegesClaimWrapper.getList();
        assertEquals(2, list.size());

        boolean aFound = false;
        boolean bFound = false;
        for (ClaimWrapper claimWrapper : list) {
            if ("A".equals(claimWrapper.getText())) {
                aFound = true;
            } else if ("B".equals(claimWrapper.getMap().get("vehicle_category_code").getText())) {
                bFound = true;
            }
        }
        assertTrue(aFound);
        assertTrue(bFound);
    }

    @Override
    protected void assertDrivingPrivilegesEquals(List<MdocDrivingPrivilege> drivingPrivileges, DrivingPrivilegesClaimWrapper drivingPrivilegesClaimWrapper) {
        // skip
    }

    @Override
    protected MdocEAAPayloadParameters getPayloadParameters() {
        return payloadParameters;
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected CBAdESSignatureParameters getKeyBindingSignatureParameters() {
        return null;
    }

    @Override
    protected MdocKeyBindingParameters getKeyBindingParameters() {
        return null;
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected String getSigningAlias() {
        return ECDSA_USER;
    }

}

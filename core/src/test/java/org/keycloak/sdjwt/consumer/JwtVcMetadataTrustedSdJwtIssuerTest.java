package org.keycloak.sdjwt.consumer;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.ClassRule;
import org.junit.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.rule.CryptoInitRule;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.TestUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public abstract class JwtVcMetadataTrustedSdJwtIssuerTest {

    @ClassRule
    public static CryptoInitRule cryptoInitRule = new CryptoInitRule();

    @Test
    public void shouldResolveIssuerVerifyingKeys() throws VerificationException {
        String issuerUri = "https://trial.authlete.net";
        TrustedSdJwtIssuer trustedIssuer = new JwtVcMetadataTrustedSdJwtIssuer(issuerUri);
        IssuerSignedJWT issuerSignedJWT = exampleIssuerSignedJWT(issuerUri);
        trustedIssuer.resolveIssuerVerifyingKeys(issuerSignedJWT);
    }

    private IssuerSignedJWT exampleIssuerSignedJWT(String issuerUri) {
        String sdJwtVPString = TestUtils.readFileAsString(getClass(), "sdjwt/s20.1-sdjwt+kb.txt");
        IssuerSignedJWT issuerSignedJWT = SdJwtVP.of(sdJwtVPString).getIssuerSignedJWT();
        ((ObjectNode) issuerSignedJWT.getPayload()).put("iss", issuerUri);
        return issuerSignedJWT;
    }
}

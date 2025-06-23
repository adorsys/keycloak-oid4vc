package org.keycloak.protocol.oid4vc.issuance.keybinding;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.VCIssuanceContext;
import org.keycloak.protocol.oid4vc.issuance.VCIssuerException;
import org.keycloak.protocol.oid4vc.model.AttestationProof;
import org.keycloak.protocol.oid4vc.model.Proof;
import org.keycloak.jose.jwk.JWK;


public class AttestationProofValidatorFactory extends AbstractProofValidator {

   @Override
   public String getProofType(){
    return ProofType.ATTESTATION;
   }

   @Override
   public ProofValidator create(KeycloakSession session){
    return new AttestationProofValidator(session);
   }
   
} 
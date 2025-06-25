package org.keycloak.protocol.oid4vc.issuance.keybinding;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.ProofType;


public class AttestationProofValidatorFactory implements ProofValidatorFactory {

   @Override
   public String getId(){
    return ProofType.ATTESTATION;
   }

   @Override
   public ProofValidator create(KeycloakSession session){
    return new AttestationProofValidator(session);
   }
   
}

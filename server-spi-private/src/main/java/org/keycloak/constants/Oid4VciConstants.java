/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.constants;

/**
 * @author Pascal Knüppel
 */
public final class Oid4VciConstants {

    public static final String OID4VC_PROTOCOL = "oid4vc";

    public static final String C_NONCE_LIFETIME_IN_SECONDS = "vc.c-nonce-lifetime-seconds";

    public static final String CREDENTIAL_SUBJECT = "credentialSubject";

    // --- Mappers ---
    public static final String CLAIM_NAME = "claim.name";
    public static final String USER_ATTRIBUTE_KEY = "userAttribute";
    public static final String AGGREGATE_ATTRIBUTES_KEY = "aggregateAttributes";
    public static final String MAPPER_ID_ISSUED_AT_TIME = "oid4vc-issued-at-time-claim-mapper";
    public static final String TRUNCATE_TO_TIME_UNIT_KEY = "truncateToTimeUnit";
    public static final String VALUE_SOURCE = "valueSource";
    public static final String MAPPER_ID_SUBJECT_ID = "oid4vc-subject-id-mapper";
    public static final String DEFAULT_CLAIM_NAME_ROLES = "roles";
    public static final String MAPPER_ID_TARGET_ROLE = "oid4vc-target-role-mapper";
    public static final String MAPPER_ID_VC_TYPE = "oid4vc-vc-type-mapper";
    public static final String TYPE_KEY_VC_TYPE = "vcTypeProperty";
    public static final String DEFAULT_VC_TYPE = "VerifiableCredential";
    public static final String MAPPER_ID_USER_ATTRIBUTE = "oid4vc-user-attribute-mapper";
    public static final String MAPPER_ID_GENERATED_ID = "oid4vc-generated-id-mapper";
    public static final String MAPPER_ID_CONTEXT = "oid4vc-context-mapper";
    public static final String TYPE_KEY_CONTEXT = "context";
    public static final String MAPPER_ID_STATIC_CLAIM = "oid4vc-static-claim-mapper";
    public static final String STATIC_CLAIM_KEY = "staticValue";

    // --- Endpoints/Well-Known ---
    public static final String PROVIDER_ID_WELL_KNOWN = "openid-credential-issuer";
    public static final String VC_KEY = "vc";
    public static final String NONCE_PATH = "nonce";
    public static final String CREDENTIAL_PATH = "credential";
    public static final String CREDENTIAL_OFFER_PATH = "credential-offer/";
    public static final String RESPONSE_TYPE_IMG_PNG = "image/png";
    public static final String CREDENTIAL_OFFER_URI_CODE_SCOPE = "credential-offer";

    // --- Model/Format/Proof ---
    public static final String MULTIVALUED_STRING_SEPARATOR = ",";
    public static final String DOT_SEPARATOR = ".";
    public static final String VERIFIABLE_CREDENTIAL_TYPE_KEY = "vct";
    public static final String CREDENTIAL_BUILD_CONFIG_KEY = "credential_build_config";
    public static final String FORMAT_LDP_VC = "ldp_vc";
    public static final String FORMAT_JWT_VC = "jwt_vc";
    public static final String FORMAT_SD_JWT_VC = "vc+sd-jwt";
    public static final String PROOF_TYPE_JWT = "jwt";
    public static final String PROOF_TYPE_LD_PROOF = "ldp_vp";
    public static final String VC_CONTEXT_V1 = "https://www.w3.org/ns/credentials/v1";
    public static final String VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2";

    // --- Keybinding/Credential Builder ---
    public static final String PROOF_JWT_TYP = "openid4vci-proof+jwt";
    public static final String SPI_NAME_C_NONCE = "oid4vci-c-nonce-spi";
    public static final String PROVIDER_ID_JWT_C_NONCE_BUILDER = "oid4vci-jwt-c-nonce-builder";
    public static final String SOURCE_ENDPOINT = "source_endpoint";
    public static final String ISSUER_CLAIM = "iss";
    public static final String VERIFIABLE_CREDENTIAL_TYPE_CLAIM = "vct";

    // --- Signing ---
    public static final String PROOF_PURPOSE_ASSERTION = "assertionMethod";
    public static final String PROOF_KEY = "proof";
    public static final String PROOF_TYPE_ED25519_2018 = "Ed25519Signature2018";

    // --- New constant for JWT VC Issuer provider id
    public static final String PROVIDER_ID_JWT_VC_ISSUER = "jwt-vc-issuer";

    // --- SupportedCredentialConfiguration keys ---
    public static final String FORMAT_KEY = "format";
    public static final String SCOPE_KEY = "scope";
    public static final String CRYPTOGRAPHIC_BINDING_METHODS_SUPPORTED_KEY = "cryptographic_binding_methods_supported";
    public static final String CREDENTIAL_SIGNING_ALG_VALUES_SUPPORTED_KEY = "credential_signing_alg_values_supported";
    public static final String DISPLAY_KEY = "display";
    public static final String PROOF_TYPES_SUPPORTED_KEY = "proof_types_supported";
    public static final String CLAIMS_KEY = "claims";
    public static final String CREDENTIAL_DEFINITION_KEY = "credential_definition";

    // --- DisplayObject keys ---
    public static final String NAME_KEY = "name";
    public static final String LOCALE_KEY = "locale";
    public static final String LOGO_KEY = "logo";
    public static final String DESCRIPTION_KEY = "description";
    public static final String BG_COLOR_KEY = "background_color";
    public static final String TEXT_COLOR_KEY = "text_color";

    // --- JwtCredentialBuilder keys ---
    public static final String VC_CLAIM_KEY = "vc";
    public static final String ID_CLAIM_KEY = "id";

    // --- CredentialBuildConfig keys ---
    public static final String TOKEN_JWS_TYPE_KEY = "token_jws_type";
    public static final String HASH_ALGORITHM_KEY = "hash_algorithm";
    public static final String VISIBLE_CLAIMS_KEY = "visible_claims";
    public static final String NUMBER_OF_DECOYS_KEY = "decoys";
    public static final String SIGNING_KEY_ID_KEY = "signing_key_id";
    public static final String OVERRIDE_KEY_ID_KEY = "override_key_id";
    public static final String SIGNING_ALGORITHM_KEY = "signing_algorithm";
    public static final String LDP_PROOF_TYPE_KEY = "ldp_proof_type";

    // --- SdJwtCredentialBody keys ---
    public static final String CNF_CLAIM = "cnf";
    public static final String JWK_CLAIM = "jwk";

    // --- CredentialBuilderUtils keys ---
    public static final String ID_TEMPLATE = "urn:uuid:%s";

    private Oid4VciConstants() {
    }
}

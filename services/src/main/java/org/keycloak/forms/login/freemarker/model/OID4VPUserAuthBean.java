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
 */

package org.keycloak.forms.login.freemarker.model;

import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;

import java.net.URI;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthBean {

    private final String realm;
    private final URI baseUri;

    public OID4VPUserAuthBean(RealmModel realm, URI baseUri) {
        this.realm = realm.getName();
        this.baseUri = baseUri;
    }

    /**
     * URL to initiate the OID4VP authentication request
     */
    public String getRequestUrl() {
        return Urls.realmBase(baseUri)
                .path(OID4VPUserAuthEndpoint.class, "getAuthenticationRequest")
                .build(realm)
                .toString();
    }

    /**
     * URL to continue OIDC flow upon successful OID4VP authentication
     */
    public String getLoginActionUrl() {
        return Urls.loginActionsBase(baseUri)
                .path(LoginActionsService.class, "oid4vpAuthLogin")
                .build(realm)
                .toString();
    }
}

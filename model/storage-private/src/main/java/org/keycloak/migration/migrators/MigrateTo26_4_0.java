/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 *  and other contributors as indicated by the @author tags.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.keycloak.migration.migrators;

import org.keycloak.migration.ModelVersion;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionProvider;
import org.jboss.logging.Logger;
import org.keycloak.models.utils.DefaultAuthenticationFlows;

public class MigrateTo26_4_0 extends RealmMigration {

    private static final Logger LOG = Logger.getLogger(MigrateTo24_0_0.class);
    public static final ModelVersion VERSION = new ModelVersion("26.4.0");

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

    @Override
    public void migrate(KeycloakSession session) {
        UserSessionProvider provider = session.getProvider(UserSessionProvider.class);
        if (provider != null) {
            provider.migrate(VERSION.toString());
        }
        super.migrate(session);
    }

    @Override
    public void migrateRealm(KeycloakSession session, RealmModel realm) {
        if (realm.getFlowByAlias(DefaultAuthenticationFlows.OID4VP_AUTH_FLOW) == null) {
            LOG.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());
            DefaultAuthenticationFlows.oid4vpAuthenticationFlow(realm);
        } else {
            LOG.debugf("OpenID4VP user auth flow flow already exists for realm '%s'", realm.getName());
        }
    }
}

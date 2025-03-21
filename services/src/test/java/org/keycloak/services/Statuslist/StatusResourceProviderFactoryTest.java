package org.keycloak.services.Statuslist;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.models.KeycloakSession;
import org.keycloak.statulist.StatusResourceProvider;
import org.keycloak.statulist.StatusResourceProviderFactory;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusResourceProviderFactoryTest {

    @Mock
    private KeycloakSession session;

    @Test
    public void testCreateCorrectProviderInstance() {
        StatusResourceProviderFactory factory = new StatusResourceProviderFactory();
        Object provider = factory.create(session);

        assertNotNull(provider);
        assertTrue(provider instanceof StatusResourceProvider);
    }

    @Test
    public void testFactoryId() {
        StatusResourceProviderFactory factory = new StatusResourceProviderFactory();
        String id = factory.getId();

        assertNotNull(id);
        assertEquals("token-status", id);
    }

    @Test
    public void testClose() {
        // Just ensuring it doesn't throw exception
        StatusResourceProviderFactory factory = new StatusResourceProviderFactory();
        factory.close();
    }
}

import { expect, test } from "@playwright/test";
import { login } from "../utils/login.ts";
import adminClient from "../utils/AdminClient.ts";
import { goToClientScopes } from "../utils/sidebar.ts";
import { clickSaveButton } from "../utils/form.ts";
import { clickTableToolbarItem } from "../utils/table.ts";

// Test data constants
const TEST_CLIENT_SCOPE_NAME = `oid4vci-test-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;

// OID4VCI field selectors
const OID4VCI_FIELDS = {
  CREDENTIAL_CONFIGURATION_ID: "attributes.vc🍺credential🍺configuration🍺id",
  CREDENTIAL_IDENTIFIER: "attributes.vc🍺credential🍺identifier",
  ISSUER_DID: "attributes.vc🍺issuer🍺did",
  EXPIRY_IN_SECONDS: "attributes.vc🍺expiry🍺in🍺seconds",
  FORMAT: "attributes.vc🍺format",
} as const;

// Test values
const TEST_VALUES = {
  CREDENTIAL_CONFIG: "test-cred-config-123",
  CREDENTIAL_ID: "test-cred-identifier",
  ISSUER_DID: "did:key:test123",
  EXPIRY_SECONDS: "86400",
  FORMAT: "jwt_vc",
} as const;

test.beforeAll(async () => {
  // Clean up any existing test client scope
  if (await adminClient.existsClientScope(TEST_CLIENT_SCOPE_NAME)) {
    await adminClient.deleteClientScope(TEST_CLIENT_SCOPE_NAME);
  }
});

test.afterAll(async () => {
  // Clean up the test client scope
  if (await adminClient.existsClientScope(TEST_CLIENT_SCOPE_NAME)) {
    await adminClient.deleteClientScope(TEST_CLIENT_SCOPE_NAME);
  }
});

test.beforeEach(async ({ page }) => {
  await login(page);
});

// Helper functions for OID4VCI feature checks
const isOid4vciFeatureEnabled = async (): Promise<boolean> => {
  const serverInfo = await adminClient.getServerInfo();
  const oid4vciFeature = serverInfo.features?.find(
    (feature: any) => feature.name === "OID4VC_VCI",
  );
  return oid4vciFeature?.enabled || false;
};

const isRealmVerifiableCredentialsEnabled = async (): Promise<boolean> => {
  const realm = await adminClient.getRealm("master");
  return realm?.verifiableCredentialsEnabled === true;
};

// Global feature check - if disabled, all tests should skip
const checkGlobalFeature = async () => {
  const isFeatureEnabled = await isOid4vciFeatureEnabled();
  if (!isFeatureEnabled) {
    test.skip(true, "OID4VCI global feature is not enabled");
  }
  return isFeatureEnabled;
};

test.describe("OID4VCI Client Scope Functionality", () => {
  test("should display OID4VCI fields when protocol is selected and feature enabled", async ({
    page,
  }) => {
    // Check global feature first - skip all tests if disabled
    await checkGlobalFeature();

    await goToClientScopes(page);
    await page.waitForLoadState("domcontentloaded");

    await clickTableToolbarItem(page, "Create client scope");
    await page.waitForLoadState("domcontentloaded");

    // Wait for protocol field to be visible
    await expect(page.locator("#kc-protocol")).toBeVisible();

    // Select OID4VCI protocol
    const protocolButton = page.locator("#kc-protocol");
    await protocolButton.click();

    const oid4vcOption = page.getByRole("option", {
      name: "OpenID for Verifiable Credentials",
    });
    await expect(oid4vcOption).toBeVisible();
    await oid4vcOption.click();

    // Wait for form to update
    await page.waitForLoadState("domcontentloaded");

    // Verify protocol selection
    await expect(page.locator("#kc-protocol")).toContainText(
      "OpenID for Verifiable Credentials",
    );

    // Check for OID4VCI fields or alert based on realm feature status
    const isRealmEnabled = await isRealmVerifiableCredentialsEnabled();

    if (isRealmEnabled) {
      // Realm feature is enabled - expect OID4VCI fields
      const oid4vcFields = page.locator('[data-testid*="vc"]');
      await expect(oid4vcFields).toHaveCount(5);

      // Verify all OID4VCI fields are present
      await expect(
        page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_CONFIGURATION_ID),
      ).toBeVisible();
      await expect(
        page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_IDENTIFIER),
      ).toBeVisible();
      await expect(page.getByTestId(OID4VCI_FIELDS.ISSUER_DID)).toBeVisible();
      await expect(
        page.getByTestId(OID4VCI_FIELDS.EXPIRY_IN_SECONDS),
      ).toBeVisible();
      await expect(page.getByTestId(OID4VCI_FIELDS.FORMAT)).toBeVisible();
    } else {
      // Realm feature is disabled - expect alert message
      await expect(page.getByText("OID4VCI Feature Disabled")).toBeVisible();
      await expect(
        page.getByText(/The OID4VCI.*feature is not enabled for this realm/),
      ).toBeVisible();
    }
  });

  test("should save and persist OID4VCI field values when realm feature is enabled", async ({
    page,
  }) => {
    // Check global feature first - skip all tests if disabled
    await checkGlobalFeature();

    // Check realm feature - skip if disabled (can't test save functionality)
    const isRealmEnabled = await isRealmVerifiableCredentialsEnabled();
    if (!isRealmEnabled) {
      test.skip(
        true,
        "Realm verifiable credentials feature is not enabled - cannot test save functionality",
      );
      return;
    }

    await goToClientScopes(page);
    await page.waitForLoadState("domcontentloaded");

    await clickTableToolbarItem(page, "Create client scope");
    await page.waitForLoadState("domcontentloaded");

    // Wait for protocol field to be visible
    await expect(page.locator("#kc-protocol")).toBeVisible();

    // Select OID4VCI protocol
    const { selectItem } = await import("../utils/form.ts");
    await selectItem(page, "#kc-protocol", "OpenID for Verifiable Credentials");

    // Wait for form to update
    await page.waitForLoadState("domcontentloaded");

    // Fill OID4VCI field values
    await page
      .getByTestId(OID4VCI_FIELDS.CREDENTIAL_CONFIGURATION_ID)
      .fill(TEST_VALUES.CREDENTIAL_CONFIG);
    await page
      .getByTestId(OID4VCI_FIELDS.CREDENTIAL_IDENTIFIER)
      .fill(TEST_VALUES.CREDENTIAL_ID);
    await page
      .getByTestId(OID4VCI_FIELDS.ISSUER_DID)
      .fill(TEST_VALUES.ISSUER_DID);
    await page
      .getByTestId(OID4VCI_FIELDS.EXPIRY_IN_SECONDS)
      .fill(TEST_VALUES.EXPIRY_SECONDS);
    await page.getByTestId(OID4VCI_FIELDS.FORMAT).click();
    await page.getByRole("option", { name: TEST_VALUES.FORMAT }).click();

    // Fill in the name field
    await page.getByTestId("name").fill(TEST_CLIENT_SCOPE_NAME);

    // Save the client scope
    await clickSaveButton(page);
    await expect(page.getByText("Client scope created")).toBeVisible();

    // Verify the client scope was created with correct attributes
    await page.goto("/admin/master/console/#/realms/master/client-scopes");
    await page.waitForLoadState("domcontentloaded");

    await page
      .getByPlaceholder("Search for client scope")
      .fill(TEST_CLIENT_SCOPE_NAME);

    await page.getByRole("row", { name: TEST_CLIENT_SCOPE_NAME }).click();

    // Verify OID4VCI fields contain saved values
    await expect(
      page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_CONFIGURATION_ID),
    ).toHaveValue(TEST_VALUES.CREDENTIAL_CONFIG);
    await expect(
      page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_IDENTIFIER),
    ).toHaveValue(TEST_VALUES.CREDENTIAL_ID);
    await expect(page.getByTestId(OID4VCI_FIELDS.ISSUER_DID)).toHaveValue(
      TEST_VALUES.ISSUER_DID,
    );
    await expect(
      page.getByTestId(OID4VCI_FIELDS.EXPIRY_IN_SECONDS),
    ).toHaveValue(TEST_VALUES.EXPIRY_SECONDS);
    await expect(page.getByTestId(OID4VCI_FIELDS.FORMAT)).toHaveValue(
      TEST_VALUES.FORMAT,
    );
  });

  test("should show alert when OID4VCI protocol selected but realm feature disabled", async ({
    page,
  }) => {
    // Check global feature first - skip all tests if disabled
    await checkGlobalFeature();

    // Check realm feature - skip if enabled (can't test disabled scenario)
    const isRealmEnabled = await isRealmVerifiableCredentialsEnabled();
    if (isRealmEnabled) {
      test.skip(
        true,
        "Realm verifiable credentials feature is enabled - cannot test disabled scenario",
      );
      return;
    }

    // Navigate to client scopes
    await goToClientScopes(page);
    await page.waitForLoadState("domcontentloaded");

    // Click Create client scope
    await clickTableToolbarItem(page, "Create client scope");
    await page.waitForLoadState("domcontentloaded");

    // Wait for the form to load
    await expect(page.locator("#kc-protocol")).toBeVisible();

    // Select OID4VCI protocol
    await page.locator("#kc-protocol").click();
    await expect(
      page.getByRole("option", { name: "OpenID for Verifiable Credentials" }),
    ).toBeVisible();
    await page
      .getByRole("option", { name: "OpenID for Verifiable Credentials" })
      .click();

    // Check that the alert is shown
    await expect(page.getByText("OID4VCI Feature Disabled")).toBeVisible();
    await expect(
      page.getByText(/The OID4VCI.*feature is not enabled for this realm/),
    ).toBeVisible();
  });

  test("should not display OID4VCI fields when protocol is not OID4VCI", async ({
    page,
  }) => {
    // Check global feature first - skip all tests if disabled
    await checkGlobalFeature();

    await goToClientScopes(page);
    await page.waitForLoadState("domcontentloaded");

    await clickTableToolbarItem(page, "Create client scope");
    await page.waitForLoadState("domcontentloaded");

    // Wait for protocol field to be visible
    await expect(page.locator("#kc-protocol")).toBeVisible();

    // Select OpenID Connect protocol (not OID4VCI)
    const protocolButton = page.locator("#kc-protocol");
    await protocolButton.click();

    const openidConnectOption = page.getByRole("option", {
      name: "OpenID Connect",
    });
    await expect(openidConnectOption).toBeVisible();
    await openidConnectOption.click();

    // Wait for form to update
    await page.waitForLoadState("domcontentloaded");

    // Verify OID4VCI fields are not visible
    await expect(
      page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_CONFIGURATION_ID),
    ).toBeHidden();
    await expect(
      page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_IDENTIFIER),
    ).toBeHidden();
    await expect(page.getByTestId(OID4VCI_FIELDS.ISSUER_DID)).toBeHidden();
    await expect(
      page.getByTestId(OID4VCI_FIELDS.EXPIRY_IN_SECONDS),
    ).toBeHidden();
    await expect(page.getByTestId(OID4VCI_FIELDS.FORMAT)).toBeHidden();
  });

  test("should handle OID4VCI protocol selection correctly", async ({
    page,
  }) => {
    // Check global feature first - skip all tests if disabled
    await checkGlobalFeature();

    await goToClientScopes(page);
    await page.waitForLoadState("domcontentloaded");

    await clickTableToolbarItem(page, "Create client scope");
    await page.waitForLoadState("domcontentloaded");

    // Wait for protocol field to be visible
    await expect(page.locator("#kc-protocol")).toBeVisible();

    // Test protocol dropdown functionality
    const protocolButton = page.locator("#kc-protocol");
    await protocolButton.click();

    // Verify dropdown options are available
    const oid4vcOption = page.getByRole("option", {
      name: "OpenID for Verifiable Credentials",
    });
    const openidConnectOption = page.getByRole("option", {
      name: "OpenID Connect",
    });

    await expect(oid4vcOption).toBeVisible();
    await expect(openidConnectOption).toBeVisible();

    // Select OID4VCI protocol
    await oid4vcOption.click();

    // Wait for form to update
    await page.waitForLoadState("domcontentloaded");

    // Verify protocol selection
    await expect(page.locator("#kc-protocol")).toContainText(
      "OpenID for Verifiable Credentials",
    );

    // Check realm feature status to determine what should be visible
    const isRealmEnabled = await isRealmVerifiableCredentialsEnabled();

    if (isRealmEnabled) {
      // Should see OID4VCI fields
      await expect(
        page.getByTestId(OID4VCI_FIELDS.CREDENTIAL_CONFIGURATION_ID),
      ).toBeVisible();
    } else {
      // Should see alert message
      await expect(page.getByText("OID4VCI Feature Disabled")).toBeVisible();
    }
  });
});

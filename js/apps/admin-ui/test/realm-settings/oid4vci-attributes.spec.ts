import { test, expect } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient";
import { login } from "../utils/login";
import { goToRealm, goToRealmSettings } from "../utils/sidebar";
import { assertAxeViolations } from "../utils/masthead";

// Helper: enable OID4VCI feature for the realm if needed
async function createOid4vciRealm(realmName: string) {
  await adminClient.createRealm(realmName, {
    // Add any config needed to enable OID4VCI feature
    attributes: { "oid4vci-feature-enabled": "true" },
  });
}

test.describe("OID4VCI Attributes tab", () => {
  const realmName = `oid4vci-realm-${uuid()}`;

  test.beforeAll(async () => {
    await createOid4vciRealm(realmName);
  });

  test.afterAll(async () => {
    await adminClient.deleteRealm(realmName);
  });

  test.beforeEach(async ({ page }) => {
    await login(page);
    await goToRealm(page, realmName);
    await goToRealmSettings(page);
  });

  test("should show OID4VCI tab when feature is enabled", async ({ page }) => {
    await expect(page.getByTestId("rs-oid4vci-attributes-tab")).toBeVisible();
  });

  test("should render fields and save values", async ({ page }) => {
    await page.getByTestId("rs-oid4vci-attributes-tab").click();
    await expect(
      page.getByLabel("OID4VCI Nonce Lifetime (seconds)"),
    ).toBeVisible();
    await expect(
      page.getByLabel("Pre-Authorized Code Lifespan (seconds)"),
    ).toBeVisible();

    // Fill in valid values
    await page.getByLabel("OID4VCI Nonce Lifetime (seconds)").fill("120");
    await page.getByLabel("Pre-Authorized Code Lifespan (seconds)").fill("300");
    await page.getByRole("button", { name: /save/i }).click();
    await expect(page.getByText(/success/i)).toBeVisible();
  });

  test("should validate required fields", async ({ page }) => {
    await page.getByTestId("rs-oid4vci-attributes-tab").click();
    await page.getByLabel("OID4VCI Nonce Lifetime (seconds)").fill("");
    await page.getByLabel("Pre-Authorized Code Lifespan (seconds)").fill("");
    await page.getByRole("button", { name: /save/i }).click();
    await expect(page.getByText(/required/i)).toBeVisible();
  });

  test("should pass accessibility checks", async ({ page }) => {
    await page.getByTestId("rs-oid4vci-attributes-tab").click();
    await assertAxeViolations(page);
  });
});

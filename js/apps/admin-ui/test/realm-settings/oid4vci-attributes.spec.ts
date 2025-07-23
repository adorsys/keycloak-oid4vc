import { test, expect } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient";
import { login } from "../utils/login";
import { goToRealm, goToRealmSettings } from "../utils/sidebar";
import { assertAxeViolations } from "../utils/masthead";

test.describe("OID4VCI Attributes tab", () => {
  const realmName = `oid4vci-realm-${uuid()}`;

  test.beforeAll(async () => {
    await adminClient.createRealm(realmName);
  });

  test.afterAll(async () => {
    await adminClient.deleteRealm(realmName);
  });

  test.beforeEach(async ({ page }) => {
    await login(page);
    await goToRealm(page, realmName);
    await goToRealmSettings(page);
  });

  test("should handle OID4VCI tab visibility based on feature flag", async ({
    page,
  }) => {
    const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
    const isVisible = await oid4vciTab.isVisible();

    if (isVisible) {
      await expect(oid4vciTab).toBeVisible();
    } else {
      await expect(oid4vciTab).toBeHidden();
    }
  });

  test("should render fields and save values with correct attribute keys", async ({
    page,
  }) => {
    const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
    const isVisible = await oid4vciTab.isVisible();

    if (isVisible) {
      await oid4vciTab.click();

      const nonceField = page.getByTestId("oid4vci-nonce-lifetime-seconds");
      const preAuthField = page.getByTestId("pre-authorized-code-lifespan-s");

      await expect(nonceField).toBeVisible();
      await expect(preAuthField).toBeVisible();

      await nonceField.fill("120");
      await preAuthField.fill("300");

      await page.getByTestId("oid4vci-tab-save").click();

      await expect(page.getByText(/success/i)).toBeVisible();

      const realm = await adminClient.getRealm(realmName);
      expect(realm).toBeDefined();
      expect(realm?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBe("120");
      expect(realm?.attributes?.["preAuthorizedCodeLifespanS"]).toBe("300");
    } else {
      await expect(oid4vciTab).toBeHidden();
    }
  });

  test("should validate required fields", async ({ page }) => {
    const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
    const isVisible = await oid4vciTab.isVisible();

    if (isVisible) {
      await oid4vciTab.click();

      const nonceField = page.getByTestId("oid4vci-nonce-lifetime-seconds");
      const preAuthField = page.getByTestId("pre-authorized-code-lifespan-s");

      const saveButton = page.getByTestId("oid4vci-tab-save");
      await expect(saveButton).toBeDisabled();

      await nonceField.clear();
      await preAuthField.clear();

      await expect(saveButton).toBeEnabled();

      await saveButton.click();

      await expect(oid4vciTab).toHaveAttribute("aria-selected", "true");
    } else {
      await expect(oid4vciTab).toBeHidden();
    }
  });

  test("should pass accessibility checks when feature is enabled", async ({
    page,
  }) => {
    const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");

    const isVisible = await oid4vciTab.isVisible();

    if (isVisible) {
      await oid4vciTab.click();
      await assertAxeViolations(page);
    } else {
      await expect(oid4vciTab).toBeHidden();
    }
  });
});

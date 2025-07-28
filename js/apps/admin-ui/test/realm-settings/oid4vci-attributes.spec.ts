import { test, expect } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient";
import { login } from "../utils/login";
import { goToRealm, goToRealmSettings } from "../utils/sidebar";

const realmName = `oid4vci-realm-${uuid()}`;
let isFeatureEnabled: boolean = true;

test.beforeAll(async ({ browser }) => {
  await adminClient.createRealm(realmName);
  const realm = await adminClient.getRealm(realmName);
  expect(realm).toBeDefined();

  // Check if feature is enabled using a fresh context
  const page = await browser.newPage();
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
  await page.waitForTimeout(1000);
  isFeatureEnabled = (await oid4vciTab.count()) > 0;
  await page.close();
});

test.afterAll(async () => {
  await adminClient.deleteRealm(realmName);
});

test("OID4VCI tab visibility", async ({ page }) => {
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  await page.waitForTimeout(1000);

  const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");

  if (!isFeatureEnabled) {
    // When feature is disabled, verify tab is NOT present
    await expect(oid4vciTab).toHaveCount(0);
  } else {
    // When feature is enabled, verify tab is visible
    await expect(oid4vciTab).toBeVisible();
  }
});

test("should render fields and save values with correct attribute keys", async ({
  page,
}) => {
  if (!isFeatureEnabled) {
    test.skip();
    return;
  }

  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  await page.waitForTimeout(1000);
  const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
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
});

test("should validate required fields", async ({ page }) => {
  if (!isFeatureEnabled) {
    test.skip();
    return;
  }

  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
  await oid4vciTab.click();

  const nonceField = page.getByTestId("oid4vci-nonce-lifetime-seconds");
  const preAuthField = page.getByTestId("pre-authorized-code-lifespan-s");
  const saveButton = page.getByTestId("oid4vci-tab-save");

  // Fill in values to make form dirty
  await nonceField.fill("120");
  await preAuthField.fill("300");

  await nonceField.clear();
  await preAuthField.clear();

  await expect(saveButton).toBeEnabled();

  await saveButton.click();

  await expect(
    page.getByText(
      "Please fill in all required fields, ensure each value is at least 60 seconds, and correct any errors before saving.",
    ),
  ).toBeVisible();
});

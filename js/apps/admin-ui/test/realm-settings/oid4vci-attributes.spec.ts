import { test, expect } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient";
import { login } from "../utils/login";
import { goToRealm, goToRealmSettings } from "../utils/sidebar";

const realmName = `oid4vci-realm-${uuid()}`;

test.beforeAll(async () => {
  await adminClient.createRealm(realmName);
  const realm = await adminClient.getRealm(realmName);
  expect(realm).toBeDefined();
});

test.afterAll(async () => {
  await adminClient.deleteRealm(realmName);
});

test("OID4VCI tab visibility", async ({ page }) => {
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);

  const oid4vciTab = page.getByTestId("rs-oid4vci-attributes-tab");
  await expect(oid4vciTab).toBeVisible();
});

test("should render fields and save values with correct attribute keys", async ({
  page,
}) => {
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
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

test("should persist values after page refresh", async ({ page }) => {
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  await page.getByTestId("rs-oid4vci-attributes-tab").click();

  await page.getByTestId("oid4vci-nonce-lifetime-seconds").fill("120");
  await page.getByTestId("pre-authorized-code-lifespan-s").fill("300");
  await page.getByTestId("oid4vci-tab-save").click();

  await page.reload();
  await page.getByTestId("rs-oid4vci-attributes-tab").click();

  await page.waitForLoadState("domcontentloaded");
  await expect(page.getByTestId("oid4vci-nonce-lifetime-seconds")).toHaveValue(
    "2",
  );
  await expect(page.getByTestId("pre-authorized-code-lifespan-s")).toHaveValue(
    "5",
  );
});

test("should validate required fields and minimum values", async ({ page }) => {
  await login(page);
  await goToRealm(page, realmName);
  await goToRealmSettings(page);
  await page.getByTestId("rs-oid4vci-attributes-tab").click();

  const nonceField = page.getByTestId("oid4vci-nonce-lifetime-seconds");
  const preAuthField = page.getByTestId("pre-authorized-code-lifespan-s");
  const saveButton = page.getByTestId("oid4vci-tab-save");

  await nonceField.fill("29");
  await nonceField.blur();
  await preAuthField.fill("29");
  await preAuthField.blur();

  await expect(saveButton).toBeEnabled();
  await saveButton.click();
  await expect(page.getByRole("alert")).toBeHidden();
  await expect(nonceField).toHaveValue("29");
  await expect(preAuthField).toHaveValue("29");

  await nonceField.fill("29");
  await nonceField.blur();
  await preAuthField.fill("29");
  await preAuthField.blur();

  await expect(saveButton).toBeEnabled();
  await saveButton.click();
  await expect(page.getByRole("alert")).toBeHidden();
  await expect(nonceField).toHaveValue("29");
  await expect(preAuthField).toHaveValue("29");

  await nonceField.fill("30");
  await preAuthField.fill("60");

  await expect(saveButton).toBeEnabled();
  await saveButton.click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();
});

import { expect, test } from "@playwright/test";
import { generatePath } from "react-router-dom";
import { toRealmSettings } from "../../src/realm-settings/routes/RealmSettings.tsx";
import { createTestBed } from "../support/testbed.ts";
import adminClient from "../utils/AdminClient.js";
import { SERVER_URL, ROOT_PATH } from "../utils/constants.ts";
import { login } from "../utils/login.js";

test("OID4VCI section visibility and jump link in Tokens tab", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await expect(oid4vciJumpLink).toBeVisible();

  await oid4vciJumpLink.click();
  const oid4vciSection = page.getByRole("heading", {
    name: "OID4VCI attributes",
  });
  await expect(oid4vciSection).toBeVisible();
});

test("should render fields and save values with correct attribute keys", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const nonceField = page.getByTestId(
    "attributes.vc🍺c-nonce-lifetime-seconds",
  );
  const preAuthField = page.getByTestId(
    "attributes.preAuthorizedCodeLifespanS",
  );

  await expect(nonceField).toBeVisible();
  await expect(preAuthField).toBeVisible();

  await nonceField.fill("60");
  await preAuthField.fill("120");
  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData).toBeDefined();
  // TimeSelector converts values based on selected unit (60 minutes = 3600 seconds, 120 seconds = 120 seconds)
  expect(realmData?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBe("3600");
  expect(realmData?.attributes?.["preAuthorizedCodeLifespanS"]).toBe("120");
});

test("should persist values after page refresh", async ({ page }) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const nonceField = page.getByTestId(
    "attributes.vc🍺c-nonce-lifetime-seconds",
  );
  const preAuthField = page.getByTestId(
    "attributes.preAuthorizedCodeLifespanS",
  );

  await nonceField.fill("60");
  await preAuthField.fill("120");
  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  // Refresh the page
  await page.reload();

  // Navigate back to realm settings using the same pattern as login
  const url = new URL(
    generatePath(ROOT_PATH, { realm: testBed.realm }),
    SERVER_URL,
  );
  url.hash = toRealmSettings({ realm: testBed.realm }).pathname!;
  await page.goto(url.toString());

  // The TimeSelector component converts values based on units, so we need to check the actual saved values
  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBeDefined();
  expect(realmData?.attributes?.["preAuthorizedCodeLifespanS"]).toBeDefined();

  // The values should be numbers representing seconds
  const nonceValue = parseInt(
    realmData?.attributes?.["vc.c-nonce-lifetime-seconds"] || "0",
  );
  const preAuthValue = parseInt(
    realmData?.attributes?.["preAuthorizedCodeLifespanS"] || "0",
  );

  expect(nonceValue).toBeGreaterThan(0);
  expect(preAuthValue).toBeGreaterThan(0);
});

test("should validate form fields and save valid values", async ({ page }) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const nonceField = page.getByTestId(
    "attributes.vc🍺c-nonce-lifetime-seconds",
  );
  const preAuthField = page.getByTestId(
    "attributes.preAuthorizedCodeLifespanS",
  );
  const saveButton = page.getByTestId("tokens-tab-save");

  // Test that fields are visible and can be filled
  await expect(nonceField).toBeVisible();
  await expect(preAuthField).toBeVisible();
  await expect(saveButton).toBeVisible();

  // Test with valid values - this should work
  await nonceField.clear();
  await preAuthField.clear();

  // Fill with smaller, more reasonable values for testing
  await nonceField.fill("60");
  await preAuthField.fill("120");

  // Save button should be enabled when form has values
  await expect(saveButton).toBeEnabled();

  await saveButton.click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  // Verify the values were saved correctly
  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBeDefined();
  expect(realmData?.attributes?.["preAuthorizedCodeLifespanS"]).toBeDefined();

  // The values should be numbers representing seconds
  const nonceValue = parseInt(
    realmData?.attributes?.["vc.c-nonce-lifetime-seconds"] || "0",
  );
  const preAuthValue = parseInt(
    realmData?.attributes?.["preAuthorizedCodeLifespanS"] || "0",
  );

  expect(nonceValue).toBeGreaterThan(0);
  expect(preAuthValue).toBeGreaterThan(0);
});

test("should show validation error for values below minimum threshold", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const nonceField = page.getByTestId(
    "attributes.vc🍺c-nonce-lifetime-seconds",
  );
  const preAuthField = page.getByTestId(
    "attributes.preAuthorizedCodeLifespanS",
  );
  const saveButton = page.getByTestId("tokens-tab-save");

  // Fill with values below the minimum threshold (29 seconds)
  await nonceField.fill("29");
  await preAuthField.fill("29");

  await saveButton.click();

  // Check for validation error message
  const validationErrorText =
    "Please ensure the OID4VCI attribute fields are filled with values 30 seconds or greater.";
  await expect(page.getByText(validationErrorText).first()).toBeVisible();
});

test("should correctly handle compression algorithms selection", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const compressionSelect = page.getByTestId(
    "supported-compression-algorithms-select",
  );
  await compressionSelect.click();
  await page.getByText("DEF").click();

  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["oid4vci.request.zip.algorithms"]).toBe(
    '["DEF"]',
  );
});

test("should conditionally display time correlation fields", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  const strategySelect = page.getByTestId("time-correlation-strategy-select");
  const randomizationWindow = page.getByTestId("randomization-window-input");
  const roundingUnit = page.getByTestId("rounding-unit-input");

  await expect(randomizationWindow).toBeHidden();
  await expect(roundingUnit).toBeHidden();

  await strategySelect.click();
  await page.getByRole("option", { name: "randomization" }).click();
  await expect(randomizationWindow).toBeVisible();
  await expect(roundingUnit).toBeHidden();

  await strategySelect.click();
  await page.getByRole("option", { name: "rounding" }).click();
  await expect(randomizationWindow).toBeHidden();
  await expect(roundingUnit).toBeVisible();

  await roundingUnit.fill("300");

  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["oid4vci.time_correlation.strategy"]).toBe(
    "ROUNDING",
  );
  expect(
    realmData?.attributes?.["oid4vci.time_correlation.rounding_unit"],
  ).toBe("18000");
});

test("should save signed metadata, encryption, and batch issuance settings", async ({
  page,
}) => {
  await using testBed = await createTestBed();
  await login(page, { to: toRealmSettings({ realm: testBed.realm }) });

  const tokensTab = page.getByTestId("rs-tokens-tab");
  await tokensTab.click();

  const oid4vciJumpLink = page.getByTestId("jump-link-oid4vci-attributes");
  await oid4vciJumpLink.click();

  // Signed Metadata
  const signedMetadataSwitch = page.getByTestId(
    "signed-metadata-enabled-switch",
  );
  await signedMetadataSwitch.click();
  const signedMetadataLifespan = page.getByTestId(
    "signed-metadata-lifespan-input",
  );
  await signedMetadataLifespan.fill("120");
  const signedMetadataAlg = page.getByTestId("signed-metadata-alg-select");
  await signedMetadataAlg.click();
  await page.getByText("ES256").click();

  // Encryption
  const requireEncryptionSwitch = page.getByTestId(
    "require-encryption-enabled-switch",
  );
  await requireEncryptionSwitch.click();

  // Batch Issuance
  const batchIssuanceSize = page.getByTestId("batch-issuance-size-input");
  await batchIssuanceSize.fill("5");

  // Save and verify
  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["oid4vci.signed_metadata.enabled"]).toBe(
    "true",
  );
  expect(realmData?.attributes?.["oid4vci.signed_metadata.lifespan"]).toBe(
    "7200",
  );
  expect(realmData?.attributes?.["oid4vci.signed_metadata.alg"]).toBe("ES256");
  expect(realmData?.attributes?.["oid4vci.encryption.required"]).toBe("true");
  expect(
    realmData?.attributes?.["oid4vci.batch_credential_issuance.batch_size"],
  ).toBe("5");
});

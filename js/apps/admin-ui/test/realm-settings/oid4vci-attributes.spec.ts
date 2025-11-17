import { expect, test } from "@playwright/test";
import { generatePath } from "react-router-dom";
import { toRealmSettings } from "../../src/realm-settings/routes/RealmSettings.tsx";
import { createTestBed } from "../support/testbed.ts";
import adminClient from "../utils/AdminClient.js";
import { SERVER_URL, ROOT_PATH } from "../utils/constants.ts";
import { login } from "../utils/login.js";
import { selectItem } from "../utils/form.ts";

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

  await page.reload();

  const url = new URL(
    generatePath(ROOT_PATH, { realm: testBed.realm }),
    SERVER_URL,
  );
  url.hash = toRealmSettings({ realm: testBed.realm }).pathname!;
  await page.goto(url.toString());

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBeDefined();
  expect(realmData?.attributes?.["preAuthorizedCodeLifespanS"]).toBeDefined();

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

  await expect(nonceField).toBeVisible();
  await expect(preAuthField).toBeVisible();
  await expect(saveButton).toBeVisible();

  await nonceField.clear();
  await preAuthField.clear();

  await nonceField.fill("60");
  await preAuthField.fill("120");

  await expect(saveButton).toBeEnabled();

  await saveButton.click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["vc.c-nonce-lifetime-seconds"]).toBeDefined();
  expect(realmData?.attributes?.["preAuthorizedCodeLifespanS"]).toBeDefined();

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

  await nonceField.fill("29");
  await preAuthField.fill("29");

  await saveButton.click();

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

  const compressionCheckbox = page.getByTestId("deflate-compression-checkbox");
  await compressionCheckbox.click();

  await page.getByTestId("tokens-tab-save").click();
  await expect(
    page.getByText("Realm successfully updated").first(),
  ).toBeVisible();

  const realmData = await adminClient.getRealm(testBed.realm);
  expect(realmData?.attributes?.["oid4vci.request.zip.algorithms"]).toBe("DEF");
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

  const signedMetadataSwitch = page.getByTestId(
    "attributes.oid4vci.signed_metadata.enabled",
  );
  await signedMetadataSwitch.click({ force: true });

  const signedMetadataLifespan = page.getByTestId(
    "attributes.oid4vci🍺signed_metadata🍺lifespan",
  );
  await signedMetadataLifespan.fill("120");

  const signedMetadataAlgField = page.locator(
    '[id="attributes.oid4vci🍺signed_metadata🍺alg"]',
  );
  await selectItem(page, signedMetadataAlgField, "ES256");

  const requireEncryptionSwitch = page.getByTestId(
    "attributes.oid4vci.encryption.required",
  );
  await requireEncryptionSwitch.click({ force: true });

  const batchIssuanceField = page.locator(
    '[id="attributes.oid4vci🍺batch_credential_issuance🍺batch_size"]',
  );
  const batchIssuanceInput = batchIssuanceField.locator("input");
  await batchIssuanceInput.fill("5");

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

import { Button, ActionGroup } from "@patternfly/react-core";
import { useTranslation } from "react-i18next";
import { TextControl } from "@keycloak/keycloak-ui-shared";
import { useFormContext } from "react-hook-form";
import { FormAccess } from "../../components/form/FormAccess";
import { convertAttributeNameToForm } from "../../util";
import { FormFields, SaveOptions } from "../ClientDetails";
import ClientRepresentation from "@keycloak/keycloak-admin-client/lib/defs/clientRepresentation";
import { DefaultSwitchControl } from "../../components/SwitchControl";

type OpenIdVerifiableCredentialsProps = {
  client: ClientRepresentation;
  save: (options?: SaveOptions) => void;
  reset: () => void;
};

export const OpenIdVerifiableCredentials = ({
  save,
  reset,
}: OpenIdVerifiableCredentialsProps) => {
  const { t } = useTranslation();
  const { watch } = useFormContext();

  const oid4vciEnabled = watch(
    convertAttributeNameToForm<FormFields>("attributes.oid4vci.enabled"),
    false,
  );

  return (
    <FormAccess role="manage-clients" isHorizontal>
      <DefaultSwitchControl
        name={convertAttributeNameToForm<FormFields>(
          "attributes.oid4vci.enabled",
        )}
        label={t("oid4vciEnabled")}
        labelIcon={t("oid4vciEnabledHelp")}
        stringify
      />

      {oid4vciEnabled === "true" && (
        <TextControl
          name={convertAttributeNameToForm<FormFields>(
            "attributes.oid4vci.attester_trust_idps",
          )}
          label={t("oid4vciAttesterTrustIdps")}
          labelIcon={t("oid4vciAttesterTrustIdpsHelp")}
        />
      )}

      <ActionGroup>
        <Button
          variant="secondary"
          id="oid4vciSave"
          data-testid="oid4vciSave"
          onClick={() => save()}
        >
          {t("save")}
        </Button>
        <Button
          id="oid4vciRevert"
          data-testid="oid4vciRevert"
          variant="link"
          onClick={reset}
        >
          {t("revert")}
        </Button>
      </ActionGroup>
    </FormAccess>
  );
};

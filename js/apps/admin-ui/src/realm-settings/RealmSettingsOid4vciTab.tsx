import {
  PageSection,
  ActionGroup,
  Button,
  FormGroup,
  AlertVariant,
} from "@patternfly/react-core";
import { TimeSelector } from "../components/time-selector/TimeSelector";
import { Controller, useFormContext, FormProvider } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { FormAccess } from "../components/form/FormAccess";
import { HelpItem, FormPanel, useAlerts } from "@keycloak/keycloak-ui-shared";

export const RealmSettingsOid4vciTab = ({
  realm,
  save,
}: {
  realm: any;
  save: (realm: any) => void;
}) => {
  const { t } = useTranslation();
  const { addAlert } = useAlerts();
  const form = useFormContext();
  const { formState, reset, handleSubmit } = form;

  // Show a global error notification if validation fails
  const onError = () => {
    addAlert(t("formValidationError"), AlertVariant.danger);
  };

  return (
    <PageSection variant="light">
      <FormPanel title={t("oid4vciAttributesSectionTitle")}>
        <FormProvider {...form}>
          <FormAccess
            isHorizontal
            role="manage-realm"
            className="pf-u-mt-lg"
            onSubmit={handleSubmit(save, onError)}
          >
            <FormGroup
              label={t("oid4vciNonceLifetime")}
              fieldId="oid4vciNonceLifetime"
              labelIcon={
                <HelpItem
                  helpText={t("oid4vciNonceLifetimeHelp")}
                  fieldLabelId="oid4vciNonceLifetime"
                />
              }
            >
              <Controller
                name="attributes.vc.c-nonce-lifetime-seconds"
                control={form.control}
                rules={{ required: t("required"), min: 60 }}
                render={({ field }) => (
                  <TimeSelector
                    {...field}
                    id="oid4vciNonceLifetime"
                    min={60}
                    units={["second"]}
                    value={field.value}
                    onChange={field.onChange}
                    data-testid="oid4vci-nonce-lifetime-seconds"
                  />
                )}
              />
              {formState.errors?.["attributes.vc.c-nonce-lifetime-seconds"] && (
                <span className="pf-v5-c-form__helper-text pf-m-error">
                  {
                    formState.errors["attributes.vc.c-nonce-lifetime-seconds"]
                      .message
                  }
                </span>
              )}
            </FormGroup>
            <FormGroup
              label={t("preAuthorizedCodeLifespan")}
              fieldId="preAuthorizedCodeLifespan"
              labelIcon={
                <HelpItem
                  helpText={t("preAuthorizedCodeLifespanHelp")}
                  fieldLabelId="preAuthorizedCodeLifespan"
                />
              }
            >
              <Controller
                name="attributes.preAuthorizedCodeLifespanS"
                control={form.control}
                rules={{ required: t("required"), min: 60 }}
                render={({ field }) => (
                  <TimeSelector
                    {...field}
                    id="preAuthorizedCodeLifespan"
                    min={60}
                    units={["second"]}
                    value={field.value}
                    onChange={field.onChange}
                    data-testid="pre-authorized-code-lifespan-s"
                  />
                )}
              />
              {formState.errors?.["attributes.preAuthorizedCodeLifespanS"] && (
                <span className="pf-v5-c-form__helper-text pf-m-error">
                  {
                    formState.errors["attributes.preAuthorizedCodeLifespanS"]
                      .message
                  }
                </span>
              )}
            </FormGroup>
            <ActionGroup>
              <Button
                variant="primary"
                type="submit"
                data-testid="oid4vci-tab-save"
                isDisabled={!formState.isDirty}
              >
                {t("save")}
              </Button>
              <Button variant="link" onClick={() => reset(realm)}>
                {t("revert")}
              </Button>
            </ActionGroup>
          </FormAccess>
        </FormProvider>
      </FormPanel>
    </PageSection>
  );
};

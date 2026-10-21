import { useCallback, useState } from "react";

import type { EffectiveExtensionControls, ExtensionCatalogItem } from "./extension-controls-api";
import type { ExtensionDetailUrlState } from "./extension-control-center-model";
import { ExtensionControlCenterDetail as ReadonlyExtensionControlCenterDetail } from "./extension-control-center-detail-readonly";
import { ExtensionPolicyPanel } from "./extension-policy-panel";
import { useConfirmDialog } from "./confirm-dialog";

const DRAFT_EXIT_MESSAGE = "Discard the staged extension policy draft and leave this extension?";

export function ExtensionControlCenterDetail(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
  urlState: ExtensionDetailUrlState;
  onUrlState: (state: ExtensionDetailUrlState) => void;
  onBack: () => void;
  onBroadControl?: () => void;
}) {
  const [policyDirty, setPolicyDirty] = useState(false);
  const { confirm: requestConfirmation, dialog: confirmDialog } = useConfirmDialog();
  const policyActive = props.urlState.tab === "policy";
  const guardedBack = useCallback(async () => {
    if (
      policyDirty
      && !(await requestConfirmation({
        title: "Discard unreviewed changes?",
        description: DRAFT_EXIT_MESSAGE,
        confirmLabel: "Discard changes",
        cancelLabel: "Keep editing",
        tone: "destructive",
      }))
    ) return;
    props.onBack();
  }, [policyDirty, props.onBack, requestConfirmation]);

  return <>
    {confirmDialog}
    <div>
      <ReadonlyExtensionControlCenterDetail
        {...props}
        externalPolicyPanelId="extension-policy-tabpanel"
        onBack={() => void guardedBack()}
      />
    </div>
    <div
      id="extension-policy-tabpanel"
      role="tabpanel"
      aria-labelledby="extension-tab-policy"
      hidden={!policyActive}
      aria-hidden={!policyActive}
      className="mx-auto -mt-8 w-full max-w-7xl px-4 pb-10 sm:px-6 lg:px-8"
    >
      <ExtensionPolicyPanel
        extension={props.extension}
        effective={props.effective}
        catalogDigest={props.catalogDigest}
        onRefresh={() => window.location.reload()}
        onDirtyChange={setPolicyDirty}
      />
    </div>
  </>;
}

import { useCallback, useState } from "react";

import type { EffectiveExtensionControls, ExtensionCatalogItem } from "./extension-controls-api";
import type { ExtensionDetailUrlState } from "./extension-control-center-model";
import { ExtensionControlCenterDetail as ReadonlyExtensionControlCenterDetail } from "./extension-control-center-detail-readonly";
import { ExtensionPolicyPanel } from "./extension-policy-panel";

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
  const policyActive = props.urlState.tab === "policy";
  const guardedBack = useCallback(() => {
    if (policyDirty && !window.confirm(DRAFT_EXIT_MESSAGE)) return;
    props.onBack();
  }, [policyDirty, props.onBack]);

  return <>
    <div className={policyActive ? "[&_#extension-panel-policy]:hidden" : undefined}>
      <ReadonlyExtensionControlCenterDetail {...props} onBack={guardedBack} />
    </div>
    <div
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

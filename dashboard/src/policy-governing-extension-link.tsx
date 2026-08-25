import { type MouseEvent } from "react";

import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import { resolvePolicyGoverningExtensionId } from "./policy-managed-authority";

export function GoverningExtensionLink(props: {
  policy: GuardPolicyDecision;
  onNavigate?: (pathname: string) => void;
}) {
  const extensionId = resolvePolicyGoverningExtensionId(props.policy);
  if (!extensionId) return null;
  const href = `/extensions/${encodeURIComponent(extensionId)}`;
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (!props.onNavigate) return;
    event.preventDefault();
    props.onNavigate(href);
  };
  return (
    <a href={guardAwareHref(href)} onClick={handleClick} className="mt-2 inline-flex text-xs font-semibold text-brand-blue hover:underline">
      Open governing Extension
    </a>
  );
}

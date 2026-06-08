import { FiShare2 } from "react-icons/fi";
import { ActionButton } from "../approval-center-primitives";

interface EvidenceInsightsShareButtonProps {
  onClick: () => void;
  className?: string;
}

export function EvidenceInsightsShareButton({ onClick, className }: EvidenceInsightsShareButtonProps) {
  return (
    <ActionButton onClick={onClick} className={className} aria-label="Share your Guard stats publicly">
      <span className="inline-flex items-center gap-2">
        <FiShare2 className="h-4 w-4" aria-hidden="true" />
        Share publicly
      </span>
    </ActionButton>
  );
}

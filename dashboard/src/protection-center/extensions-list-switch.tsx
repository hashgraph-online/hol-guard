import { HiMiniPlus } from "react-icons/hi2";

export type ExtensionListView = "builtin" | "custom";

interface ExtensionListSwitchProps {
  view: ExtensionListView;
  onViewChange: (view: ExtensionListView) => void;
  builtinCount: number;
  customCount: number;
  /** Custom extensions waiting on a permission decision. */
  customNeedsReviewCount: number;
  /** Absent while a search replaces the built-in list, so nothing points at a missing panel. */
  builtinPanelId?: string;
  customPanelId: string;
  /** The one Add entry point; omitted when the custom empty state carries it. */
  onAddCustom?: () => void;
}

/**
 * Chooses which list sits under the search: Guard's built-in tools or the
 * connectors and tools added on this device. Both lists share one page and one
 * search, so flipping between them keeps the reader's place instead of sending
 * them to another screen, and only one list at a time pushes the page down.
 * The custom option says when anything in it is waiting for review, because a
 * list that is out of sight must still be able to ask for attention.
 */
export function ExtensionListSwitch(props: ExtensionListSwitchProps) {
  const options: {
    view: ExtensionListView;
    label: string;
    count: number;
    panelId: string | undefined;
    attention: number;
  }[] = [
    { view: "builtin", label: "All tools", count: props.builtinCount, panelId: props.builtinPanelId, attention: 0 },
    {
      view: "custom",
      label: "Custom extensions",
      count: props.customCount,
      panelId: props.customPanelId,
      attention: props.customNeedsReviewCount,
    },
  ];
  return (
    <div className="guard-list-switch" data-testid="extension-list-switch">
      <div className="guard-list-switch-track" role="group" aria-label="Extension list">
        {options.map((option) => (
          <button
            key={option.view}
            type="button"
            className="guard-list-switch-option"
            aria-pressed={props.view === option.view}
            aria-controls={option.panelId}
            data-view={option.view}
            onClick={() => props.onViewChange(option.view)}
          >
            {option.label}
            <span className="guard-list-switch-count">{option.count.toLocaleString()}</span>
            {option.attention > 0 ? (
              <>
                <span className="guard-list-switch-dot" aria-hidden="true" />
                <span className="sr-only">{option.attention.toLocaleString()} need review</span>
              </>
            ) : null}
          </button>
        ))}
      </div>
      {props.onAddCustom ? (
        <button
          type="button"
          onClick={props.onAddCustom}
          className="guard-list-switch-add"
        >
          <HiMiniPlus className="size-4" aria-hidden="true" />
          Add custom extension
        </button>
      ) : null}
    </div>
  );
}

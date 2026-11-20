type EscapeKeyEvent = {
  key: string;
  defaultPrevented: boolean;
  preventDefault: () => void;
  stopPropagation: () => void;
};

/**
 * Keydown handler that closes an aria-modal dialog on Escape.
 *
 * It is scoped to the dialog element rather than the document so a dialog that
 * opens on top of another one (for example the approval prompt over the manager
 * drawer) closes alone and leaves the dialog beneath it open.
 */
export function closeOnEscape(onClose: () => void) {
  return (event: EscapeKeyEvent): void => {
    if (event.key !== "Escape" || event.defaultPrevented) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    onClose();
  };
}

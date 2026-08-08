/**
 * The workspace switcher, sitting in the masthead between Messaging and Fleet.
 *
 * It is next to the navigation but is not part of it, and the distinction is deliberate:
 * the nav items change *which view* you are looking at, while this changes *what the
 * views are about*. Rendering it as a sixth pill would imply "Workspace" is a destination
 * you can be on, which it never is.
 *
 * Owner-only actions are hidden rather than shown-and-disabled. A row of greyed controls
 * invites a member to wonder what they are missing; the server refuses them regardless,
 * so showing them buys nothing.
 */
import { useEffect, useRef, useState } from "react";

import { Badge } from "./ui.jsx";

export default function WorkspaceMenu({
  workspaces,
  activeId,
  currentUserId,
  onSelect,
  onCreate,
  onRename,
  onDelete,
  onLeave,
  onListDeleted,
  onRestore,
}) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState(null);
  const [draft, setDraft] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [deleted, setDeleted] = useState([]);
  const [error, setError] = useState("");
  const rootRef = useRef(null);

  const active = workspaces.find((item) => item.id === activeId) || workspaces[0] || null;
  const isOwner = active?.owner_id === currentUserId;

  function close() {
    setOpen(false);
    setMode(null);
    setDraft("");
    setConfirm("");
    setError("");
  }

  // A menu that stays open after you click elsewhere is a menu that covers what you
  // clicked on. Escape closes it too, since it is a focus trap for keyboard users.
  useEffect(() => {
    if (!open) return;
    // Fetched on open rather than continuously: it changes only when someone deletes a
    // workspace, and the masthead is mounted for the whole session.
    onListDeleted?.().then(setDeleted).catch(() => setDeleted([]));
  }, [open, onListDeleted]);

  useEffect(() => {
    if (!open) return undefined;
    const onPointer = (event) => {
      if (!rootRef.current?.contains(event.target)) close();
    };
    const onKey = (event) => {
      if (event.key === "Escape") close();
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function run(action) {
    setBusy(true);
    setError("");
    try {
      await action();
      close();
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wsmenu" ref={rootRef}>
      <button
        type="button"
        className={open ? "wsmenu__trigger is-open" : "wsmenu__trigger"}
        onClick={() => (open ? close() : setOpen(true))}
        aria-expanded={open}
        aria-haspopup="menu"
        title={active ? `Workspace: ${active.name}` : "No workspace"}
      >
        <span aria-hidden="true">▤</span>
        <span className="wsmenu__name truncate">{active?.name || "No workspace"}</span>
        <span className="wsmenu__caret" aria-hidden="true">▾</span>
      </button>

      {open && (
        <div className="wsmenu__panel reveal" role="menu">
          <div className="wsmenu__list">
            {workspaces.map((item) => (
              <button
                key={item.id}
                type="button"
                role="menuitem"
                className={item.id === active?.id ? "wsmenu__item is-active" : "wsmenu__item"}
                onClick={() => {
                  onSelect(item.id);
                  close();
                }}
              >
                <span aria-hidden="true">{item.id === active?.id ? "✓" : " "}</span>
                <span className="truncate">{item.name}</span>
                {item.owner_id === currentUserId && <Badge tone="neutral">owner</Badge>}
              </button>
            ))}
            {!workspaces.length && <p className="subtle">No workspaces yet.</p>}
          </div>

          <div className="wsmenu__divider" />

          {mode === null && (
            <div className="wsmenu__actions">
              <button type="button" className="link-btn" onClick={() => setMode("create")}>
                + New workspace
              </button>
              {active && isOwner && (
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => {
                    setDraft(active.name);
                    setMode("rename");
                  }}
                >
                  Rename
                </button>
              )}
              {active && isOwner && (
                <button type="button" className="link-btn" onClick={() => setMode("delete")}>
                  Delete
                </button>
              )}
              {active && !isOwner && (
                <button type="button" className="link-btn" onClick={() => setMode("leave")}>
                  Leave
                </button>
              )}
            </div>
          )}

          {(mode === "create" || mode === "rename") && (
            <div className="stack reveal" style={{ gap: "var(--sp-2)" }}>
              <input
                className="input"
                autoFocus
                placeholder={mode === "create" ? "Workspace name" : "New name"}
                aria-label={mode === "create" ? "New workspace name" : "New workspace name"}
                value={draft}
                onChange={(event) => setDraft(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key !== "Enter" || !draft.trim()) return;
                  run(() =>
                    mode === "create" ? onCreate(draft.trim()) : onRename(active.id, draft.trim()),
                  );
                }}
              />
              <div className="row" style={{ gap: "var(--sp-2)" }}>
                <button
                  className="btn btn--sm btn--primary"
                  disabled={busy || !draft.trim()}
                  onClick={() =>
                    run(() =>
                      mode === "create" ? onCreate(draft.trim()) : onRename(active.id, draft.trim()),
                    )
                  }
                >
                  {busy ? "Working…" : mode === "create" ? "Create" : "Rename"}
                </button>
                <button className="link-btn" onClick={() => setMode(null)} disabled={busy}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {mode === "delete" && (
            <div className="stack reveal" style={{ gap: "var(--sp-2)" }}>
              <p className="subtle">
                This removes <strong>{active.name}</strong>, every channel in it and the
                messages the relay holds — for all members, not just you, and immediately.
                You can restore it from this menu for 30 days, after which it is deleted
                for good. Restoring cannot recover copies already decrypted on anyone's
                device, and deleting never reached those in the first place.
              </p>
              <input
                className="input mono"
                autoFocus
                placeholder={`Type ${active.name} to confirm`}
                aria-label={`Type ${active.name} to confirm deletion`}
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
              />
              <div className="row" style={{ gap: "var(--sp-2)" }}>
                <button
                  className="btn btn--sm btn--danger"
                  disabled={busy || confirm !== active.name}
                  onClick={() => run(() => onDelete(active.id))}
                >
                  {busy ? "Deleting…" : "Delete permanently"}
                </button>
                <button className="link-btn" onClick={() => setMode(null)} disabled={busy}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {mode === "leave" && (
            <div className="stack reveal" style={{ gap: "var(--sp-2)" }}>
              <p className="subtle">
                You will lose access to <strong>{active.name}</strong>. Every channel you
                were in rotates its key, so nothing sent afterwards is readable to you. The
                workspace continues for everyone else.
              </p>
              <div className="row" style={{ gap: "var(--sp-2)" }}>
                <button
                  className="btn btn--sm"
                  disabled={busy}
                  onClick={() => run(() => onLeave(active.id))}
                >
                  {busy ? "Leaving…" : "Leave workspace"}
                </button>
                <button className="link-btn" onClick={() => setMode(null)} disabled={busy}>
                  Cancel
                </button>
              </div>
            </div>
          )}

          {mode === null && deleted.filter((row) => !row.expired).length > 0 && (
            <div className="wsmenu__deleted">
              <div className="eyebrow subtle">Recently deleted</div>
              {deleted
                .filter((row) => !row.expired)
                .map((row) => (
                  <div key={row.id} className="row row--between" style={{ gap: "var(--sp-2)" }}>
                    <span className="truncate subtle">
                      {row.name} · {row.restorable_for_days}d left
                    </span>
                    <button
                      type="button"
                      className="link-btn"
                      disabled={busy}
                      onClick={() => run(async () => {
                        await onRestore(row.id);
                        setDeleted((rows) => rows.filter((item) => item.id !== row.id));
                      })}
                    >
                      Restore
                    </button>
                  </div>
                ))}
            </div>
          )}

          {error && <p className="wsmenu__error">{error}</p>}
        </div>
      )}
    </div>
  );
}

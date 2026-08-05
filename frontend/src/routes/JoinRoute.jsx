import { useCallback, useEffect, useState } from "react";
import { inviteApi } from "../lib/api.js";
import { Alert, Badge, Mark, Panel, Spinner } from "../components/ui.jsx";

const STATE_COPY = {
  expired: "This invite has expired.",
  revoked: "This invite was revoked by its creator.",
  used_up: "This invite has already been used the maximum number of times.",
};

/**
 * Redeems an invite code taken from the URL.
 *
 * Accepting requires a signed-in identity with published keys, because joining opens a
 * two-party channel and the peer's side of the handshake needs a key bundle to verify
 * against. The preview below is deliberately readable before sign-in so nobody has to
 * register just to find out what they were sent.
 */
export default function JoinRoute({ code, user, onJoined, onDismiss }) {
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  useEffect(() => {
    let cancelled = false;
    inviteApi
      .preview(code)
      .then((data) => {
        if (!cancelled) setPreview(data);
      })
      .catch((caught) => {
        if (!cancelled) setError(caught.message);
      });
    return () => {
      cancelled = true;
    };
  }, [code]);

  const accept = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const joined = await inviteApi.accept(code);
      setResult(joined);
      onJoined?.(joined);
    } catch (caught) {
      setError(caught.message);
    } finally {
      setBusy(false);
    }
  }, [code, onJoined]);

  if (!preview && !error) return <Spinner label="Checking invite…" />;

  return (
    <div className="auth">
      <Panel eyebrow="Invitation" title={preview?.workspace_name || "Invite"}>
        <div className="stack" style={{ maxWidth: "440px" }}>
          <div className="row" style={{ gap: "var(--sp-3)" }}>
            <Mark large />
            <div>
              {preview?.invited_by && (
                <p className="muted">
                  <strong>{preview.invited_by}</strong> invited you to a secure workspace.
                </p>
              )}
              {preview && (
                <Badge tone={preview.valid ? "good" : "critical"}>
                  {preview.valid ? "valid invite" : preview.state}
                </Badge>
              )}
            </div>
          </div>

          {preview && !preview.valid && (
            <Alert tone="error">{STATE_COPY[preview.state] || "This invite is not usable."}</Alert>
          )}
          {error && <Alert tone="error">{error}</Alert>}

          {result ? (
            <>
              <Alert tone="good">
                Joined <strong>{result.server_name}</strong>. An encrypted channel with{" "}
                <strong>{result.peer}</strong> is open.
              </Alert>
              <button className="btn btn--primary" onClick={onDismiss}>
                Open messaging
              </button>
            </>
          ) : !user ? (
            <>
              <Alert tone="info">
                Sign in or register to accept. Your keys are generated in this browser and
                never leave it.
              </Alert>
              <button className="btn btn--primary" onClick={onDismiss}>
                Continue to sign in
              </button>
            </>
          ) : (
            <>
              {!user.key_verified && (
                <Alert tone="warning">
                  Publish your key bundle first — a channel cannot be opened without it.
                </Alert>
              )}
              <div className="row" style={{ gap: "var(--sp-2)" }}>
                <button
                  className="btn btn--primary"
                  disabled={busy || !preview?.valid || !user.key_verified}
                  onClick={accept}
                >
                  {busy ? "Joining…" : "Accept invite"}
                </button>
                <button className="btn" onClick={onDismiss}>
                  Not now
                </button>
              </div>
            </>
          )}
        </div>
      </Panel>
    </div>
  );
}

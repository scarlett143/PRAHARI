/** Shared primitives for the PRAHARI console. */

export function Panel({ title, eyebrow, description, actions, children, flush = false, ...rest }) {
  return (
    <section className={flush ? "panel panel--flush" : "panel"} {...rest}>
      {(title || actions || eyebrow) && (
        <header className="panel__header" style={flush ? { padding: "var(--sp-4)", marginBottom: 0 } : undefined}>
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            {title && <h3>{title}</h3>}
            {description && <p className="subtle">{description}</p>}
          </div>
          {actions}
        </header>
      )}
      {children}
    </section>
  );
}

const BADGE_TONES = {
  good: { className: "badge badge--good", glyph: "✓" },
  warning: { className: "badge badge--warning", glyph: "!" },
  critical: { className: "badge badge--critical", glyph: "✕" },
  accent: { className: "badge badge--accent", glyph: "" },
  neutral: { className: "badge", glyph: "" },
};

/**
 * Status is never carried by colour alone: every tone ships a glyph and the
 * label text, so the meaning survives greyscale, CVD, and forced-colors mode.
 */
export function Badge({ tone = "neutral", children, glyph, title }) {
  const spec = BADGE_TONES[tone] ?? BADGE_TONES.neutral;
  const mark = glyph ?? spec.glyph;
  return (
    // `title` carries supporting detail that would not fit in the badge itself -- a
    // containment reason, say. It is supplementary by design: the badge text alone still
    // says what the state is, since a tooltip is unreachable on touch.
    <span className={spec.className} title={title}>
      {mark && <span aria-hidden="true">{mark}</span>}
      {children}
    </span>
  );
}

export function StatTile({ label, value, unit, meta, tone }) {
  return (
    <div className="tile">
      <span className="tile__label">{label}</span>
      <span className="tile__value" style={tone ? { color: `var(--${tone})` } : undefined}>
        {value}
        {unit && <span className="tile__unit">{unit}</span>}
      </span>
      {meta && <span className="tile__meta">{meta}</span>}
    </div>
  );
}

const ALERT_GLYPHS = { error: "✕", warning: "!", good: "✓", info: "i" };

export function Alert({ tone = "info", title, children }) {
  const className = tone === "info" ? "alert" : `alert alert--${tone}`;
  return (
    <div className={className} role={tone === "error" ? "alert" : "status"}>
      <span className="alert__icon" aria-hidden="true">{ALERT_GLYPHS[tone]}</span>
      <div>
        {title && <strong>{title}</strong>}
        <div>{children}</div>
      </div>
    </div>
  );
}

export function EmptyState({ title, children, action }) {
  return (
    <div className="empty">
      <p className="empty__title">{title}</p>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  );
}

export function Field({ label, hint, id, children }) {
  return (
    <label className="field" htmlFor={id}>
      <span className="field__label">{label}</span>
      {children}
      {hint && <span className="field__hint">{hint}</span>}
    </label>
  );
}

export function Spinner({ label = "Loading" }) {
  return (
    <div className="center-screen">
      <div className="spinner" role="status" aria-label={label} />
      <p className="subtle">{label}</p>
    </div>
  );
}

export function Mark({ large = false }) {
  return <div className={large ? "mark mark--lg" : "mark"} aria-hidden="true">P</div>;
}

/**
 * The primary console navigation.
 *
 * Adapted from React Bits' GooeyNav (https://reactbits.dev/components/gooey-nav), chosen
 * over its siblings for one concrete reason: it is the only navigation component there
 * built from React and CSS alone. PillNav, StaggeredMenu, CardNav and BubbleMenu need
 * GSAP and Dock needs `motion` -- 40-120 KB that every cold load would pull from a shared
 * 2-core box that also serves the operator's other sites. This costs about 4 KB.
 *
 * The effect is two absolutely-positioned overlays tracking the active item: a blurred,
 * high-contrast layer whose `blur -> contrast` pair fuses overlapping circles into one
 * blob (the "gooey" filter), and a plain text layer above it. Particles are real DOM
 * nodes appended for the length of one animation and then removed.
 *
 * Four things were changed from upstream, each because the original assumption does not
 * hold here:
 *
 *   1. It is controlled. Upstream owns `activeIndex` internally, which desynchronises the
 *      moment anything else changes the view -- opening a link console does exactly that.
 *   2. Items are <button>, not <a href>. There is no router in this app; anchors would
 *      push history entries for a view change and hand the browser a navigation to cancel.
 *   3. Motion is opt-out. Upstream animates unconditionally; the particle burst is a
 *      vestibular trigger, so `prefers-reduced-motion` drops it and the pill moves plainly.
 *   4. Timers are tracked and cleared. Upstream's per-particle `setTimeout` outlives
 *      unmount and fires against a detached tree.
 */
import { useCallback, useEffect, useRef } from "react";

const ANIMATION_MS = 600;
const PARTICLE_COUNT = 15;
/** Where a particle starts and ends, in px from the centre of the active item. */
const PARTICLE_DISTANCES = [90, 10];
const PARTICLE_ROTATION = 100;
const TIME_VARIANCE = 300;

const jitter = (n = 1) => n / 2 - Math.random() * n;

function pointOnCircle(distance, index, total) {
  const angle = ((360 + jitter(8)) / total) * index * (Math.PI / 180);
  return [distance * Math.cos(angle), distance * Math.sin(angle)];
}

export default function GooeyNav({ items, activeId, onSelect, label = "Primary" }) {
  const containerRef = useRef(null);
  const listRef = useRef(null);
  const filterRef = useRef(null);
  const textRef = useRef(null);
  //: Every pending particle timeout, so unmount can cancel them rather than let them fire
  //: against a tree that no longer exists.
  const timers = useRef(new Set());

  const activeIndex = Math.max(0, items.findIndex((item) => item.id === activeId));

  /** Park the two overlays exactly over the active item. */
  const positionOverlays = useCallback(() => {
    const container = containerRef.current;
    const target = listRef.current?.children[activeIndex];
    if (!container || !target || !filterRef.current || !textRef.current) return;

    const containerBox = container.getBoundingClientRect();
    const targetBox = target.getBoundingClientRect();
    const box = {
      left: `${targetBox.x - containerBox.x}px`,
      top: `${targetBox.y - containerBox.y}px`,
      width: `${targetBox.width}px`,
      height: `${targetBox.height}px`,
    };
    Object.assign(filterRef.current.style, box);
    Object.assign(textRef.current.style, box);
    textRef.current.textContent = target.textContent;
  }, [activeIndex]);

  function burst() {
    const host = filterRef.current;
    if (!host) return;

    host.style.setProperty("--time", `${ANIMATION_MS * 2 + TIME_VARIANCE}ms`);
    for (let index = 0; index < PARTICLE_COUNT; index += 1) {
      const life = ANIMATION_MS * 2 + jitter(TIME_VARIANCE * 2);
      const [startX, startY] = pointOnCircle(PARTICLE_DISTANCES[0], PARTICLE_COUNT - index, PARTICLE_COUNT);
      const [endX, endY] = pointOnCircle(
        PARTICLE_DISTANCES[1] + jitter(7),
        PARTICLE_COUNT - index,
        PARTICLE_COUNT,
      );
      const spin = jitter(PARTICLE_ROTATION / 10);
      const rotate = spin > 0 ? (spin + PARTICLE_ROTATION / 20) * 10 : (spin - PARTICLE_ROTATION / 20) * 10;

      const particle = document.createElement("span");
      particle.className = "gooey__particle";
      const point = document.createElement("span");
      point.className = "gooey__point";
      particle.appendChild(point);

      for (const [name, value] of [
        ["--start-x", `${startX}px`],
        ["--start-y", `${startY}px`],
        ["--end-x", `${endX}px`],
        ["--end-y", `${endY}px`],
        ["--time", `${life}ms`],
        ["--scale", `${1 + jitter(0.2)}`],
        ["--rotate", `${rotate}deg`],
      ]) {
        particle.style.setProperty(name, value);
      }

      host.appendChild(particle);
      const timer = setTimeout(() => {
        particle.remove();
        timers.current.delete(timer);
      }, life);
      timers.current.add(timer);
    }
  }

  function select(id, index) {
    if (id === activeId) return;
    onSelect(id);

    // Reduced motion still gets the pill, which is what conveys *which* item is active.
    // Only the decorative burst is dropped.
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;

    const target = listRef.current?.children[index];
    if (target) {
      const container = containerRef.current;
      const containerBox = container.getBoundingClientRect();
      const targetBox = target.getBoundingClientRect();
      Object.assign(filterRef.current.style, {
        left: `${targetBox.x - containerBox.x}px`,
        top: `${targetBox.y - containerBox.y}px`,
        width: `${targetBox.width}px`,
        height: `${targetBox.height}px`,
      });
    }

    filterRef.current?.querySelectorAll(".gooey__particle").forEach((node) => node.remove());
    if (textRef.current) {
      textRef.current.classList.remove("is-active");
      // Force a reflow so removing and re-adding the class restarts the animation rather
      // than being coalesced into no change at all.
      void textRef.current.offsetWidth;
      textRef.current.classList.add("is-active");
    }
    burst();
  }

  useEffect(() => {
    positionOverlays();
    textRef.current?.classList.add("is-active");

    // The active pill is positioned in pixels, so it has to be recomputed whenever the
    // bar is laid out again -- a window resize, a label changing width, or a webfont
    // swapping in after first paint.
    const observer = new ResizeObserver(positionOverlays);
    if (containerRef.current) observer.observe(containerRef.current);
    if (listRef.current) observer.observe(listRef.current);
    return () => observer.disconnect();
  }, [positionOverlays]);

  useEffect(() => {
    const pending = timers.current;
    return () => {
      pending.forEach(clearTimeout);
      pending.clear();
    };
  }, []);

  return (
    <div className="gooey" ref={containerRef}>
      <nav aria-label={label}>
        <ul className="gooey__list" ref={listRef}>
          {items.map((item, index) => {
            const isActive = item.id === activeId;
            return (
              <li key={item.id} className={isActive ? "gooey__item is-active" : "gooey__item"}>
                <button
                  type="button"
                  onClick={() => select(item.id, index)}
                  aria-current={isActive ? "page" : undefined}
                  title={item.title}
                >
                  <span aria-hidden="true">{item.glyph}</span>
                  <span className="gooey__label">{item.label}</span>
                </button>
              </li>
            );
          })}
        </ul>
      </nav>
      {/* Both overlays are decorative duplicates of the active label; the real, readable
          one is the button above. Announcing them would repeat it three times. */}
      <span className="gooey__effect gooey__effect--filter" ref={filterRef} aria-hidden="true" />
      <span className="gooey__effect gooey__effect--text" ref={textRef} aria-hidden="true" />
    </div>
  );
}

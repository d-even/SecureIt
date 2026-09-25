// ============================================================
// Hero specimen: three visually identical copies, each with its
// own hidden fingerprint positions (mirrors text_watermark.py,
// which embeds the session ID after whitespace, 4 times per copy).
// ============================================================

const RECIPIENTS = [
  { name: "P. Kapoor", marker: "A" },
  { name: "S. Mehta", marker: "B" },
  { name: "A. Rao", marker: "C" },
];

const DOC_TITLE = "Q3 Board Briefing";
const DOC_PARAS = [
  "Revenue for the quarter came in ahead of plan, driven by the enterprise segment and two renewals signed in the final week.",
  "Headcount will stay flat through Q4. The hiring freeze applies to all non-engineering roles until the review in January.",
  "The acquisition shortlist is attached. Do not forward or discuss outside the leadership group.",
];

// Small deterministic hash so each recipient always gets the same
// positions and session ID across page loads.
function hashString(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function seededRandom(seed) {
  let s = seed || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5; s >>>= 0;
    return s / 4294967296;
  };
}

function sessionIdFor(name) {
  const rand = seededRandom(hashString(name));
  let out = "";
  for (let i = 0; i < 8; i++) out += Math.floor(rand() * 16).toString(16);
  return out;
}

function buildDoc(recipient) {
  const rand = seededRandom(hashString(recipient.name + "positions"));
  const allWords = DOC_PARAS.map((p) => p.split(" "));
  const totalGaps = allWords.reduce((n, words) => n + words.length - 1, 0);

  // pick 4 distinct gap indexes (4 embedded copies per recipient)
  const picks = new Set();
  while (picks.size < 4) picks.add(Math.floor(rand() * totalGaps));

  const page = document.createElement("div");
  page.className = "doc-page";

  const h = document.createElement("h4");
  h.textContent = DOC_TITLE;
  page.appendChild(h);

  let gapIndex = 0;
  allWords.forEach((words) => {
    const p = document.createElement("p");
    words.forEach((word, i) => {
      p.appendChild(document.createTextNode(word));
      if (i < words.length - 1) {
        p.appendChild(document.createTextNode(" "));
        if (picks.has(gapIndex)) {
          const fp = document.createElement("span");
          fp.className = "fp";
          fp.setAttribute("aria-hidden", "true");
          p.appendChild(fp);
        }
        gapIndex++;
      }
    });
    page.appendChild(p);
  });

  const marker = document.createElement("span");
  marker.className = "doc-marker";
  marker.setAttribute("aria-hidden", "true");
  marker.textContent = recipient.marker;
  page.appendChild(marker);

  const label = document.createElement("div");
  label.className = "doc-label";
  label.innerHTML =
    `<span class="doc-name">${recipient.name}</span>` +
    `<span class="doc-sid" title="Session ID">${sessionIdFor(recipient.name)}</span>`;

  const wrap = document.createElement("div");
  wrap.className = "doc";
  wrap.appendChild(page);
  wrap.appendChild(label);
  return wrap;
}

const docsEl = document.getElementById("docs");
RECIPIENTS.forEach((r) => docsEl.appendChild(buildDoc(r)));

const revealBtn = document.getElementById("reveal-btn");
const captionEl = document.getElementById("specimen-caption");
const CAPTION_HIDDEN = captionEl.textContent.trim();
const CAPTION_SHOWN =
  "Each yellow mark is where a hidden copy of that recipient's session ID sits. " +
  "Paste any fragment of a copy and the ID can still be recovered.";

revealBtn.addEventListener("click", () => {
  const on = docsEl.classList.toggle("revealed");
  revealBtn.setAttribute("aria-pressed", String(on));
  revealBtn.textContent = on ? "Hide fingerprints" : "Reveal fingerprints";
  captionEl.textContent = on ? CAPTION_SHOWN : CAPTION_HIDDEN;
});

// ============================================================
// Isometric architecture diagram
// ============================================================

const SVG_NS = "http://www.w3.org/2000/svg";

function isoBox(cx, groundY, w, h) {
  const topCY = groundY - h;
  const N = [cx, topCY - w / 2];
  const E = [cx + w, topCY];
  const S = [cx, topCY + w / 2];
  const W = [cx - w, topCY];
  const S2 = [cx, groundY + w / 2];
  const E2 = [cx + w, groundY];
  const W2 = [cx - w, groundY];
  const left = [W, S, S2, W2];
  return {
    top: [N, E, S, W],
    left,
    right: [S, E, E2, S2],
    topCY,
    leftCentroid: [
      left.reduce((a, p) => a + p[0], 0) / 4,
      left.reduce((a, p) => a + p[1], 0) / 4,
    ],
  };
}

function polygon(points, cls) {
  const el = document.createElementNS(SVG_NS, "polygon");
  el.setAttribute("points", points.map((p) => p.join(",")).join(" "));
  el.setAttribute("class", cls);
  return el;
}

// Tall boxes get a vertical label; flat boxes get one that follows the
// slope of the left face (isometric edge angle = atan(1/2) = 26.57deg).
function label(x, y, text, isTall) {
  const t = document.createElementNS(SVG_NS, "text");
  const angle = isTall ? -90 : 26.57;
  t.setAttribute("x", x);
  t.setAttribute("y", y);
  t.setAttribute("transform", `rotate(${angle} ${x} ${y})`);
  t.setAttribute("text-anchor", "middle");
  t.setAttribute("dominant-baseline", "middle");
  t.setAttribute("class", "iso-label");
  t.textContent = text;
  return t;
}

function addBox(group, cx, groundY, w, h, text) {
  const box = isoBox(cx, groundY, w, h);
  group.appendChild(polygon(box.left, "f-left"));
  group.appendChild(polygon(box.right, "f-right"));
  group.appendChild(polygon(box.top, "f-top"));
  if (text) group.appendChild(label(box.leftCentroid[0], box.leftCentroid[1], text, h > w));
  return box;
}

function layerGroup(n) {
  const g = document.createElementNS(SVG_NS, "g");
  g.setAttribute("class", "iso-layer");
  g.dataset.layer = String(n);
  return g;
}

function buildDiagram() {
  const svg = document.getElementById("iso-svg");

  const g0 = layerGroup(0);
  addBox(g0, 450, 490, 240, 50, "SecureShare protocol");
  svg.appendChild(g0);

  const g1 = layerGroup(1);
  const b1 = addBox(g1, 350, 450, 64, 40, "Watermark");
  const b2 = addBox(g1, 450, 410, 64, 40, "Session ID");
  const b3 = addBox(g1, 550, 450, 64, 40, "ECC");
  svg.appendChild(g1);

  const g2 = layerGroup(2);
  const t1 = addBox(g2, 350, b1.topCY, 40, 96, "Record");
  const t2 = addBox(g2, 450, b2.topCY, 40, 96, "ML-DSA-65");
  const t3 = addBox(g2, 550, b3.topCY, 40, 96, "Signature");
  svg.appendChild(g2);

  const g3 = layerGroup(3);
  addBox(g3, 350, t1.topCY, 36, 70, "Endorse");
  addBox(g3, 450, t2.topCY, 36, 70, "Hash chain");
  addBox(g3, 550, t3.topCY, 36, 70, "Lookup");
  svg.appendChild(g3);
}

buildDiagram();

// ============================================================
// Scrollytelling: reveal layers up to the active step, highlight
// the active one, and move the diagram to the side opposite the text.
// ============================================================

const steps = document.querySelectorAll(".step");
const stickyEl = document.getElementById("arch-sticky");
const layers = document.querySelectorAll(".iso-layer");
let visibleSteps = 0;

function setLayer(n, textSide) {
  layers.forEach((g) => {
    const idx = Number(g.dataset.layer);
    g.classList.toggle("revealed", idx <= n);
    g.classList.toggle("current", idx === n);
  });
  stickyEl.classList.remove("side-left", "side-right");
  // text on the left -> diagram shifts right, and vice versa
  stickyEl.classList.add(textSide === "left" ? "side-right" : "side-left");
}

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        visibleSteps++;
        setLayer(Number(entry.target.dataset.layer), entry.target.dataset.side);
      } else {
        visibleSteps = Math.max(0, visibleSteps - 1);
      }
    });
    stickyEl.classList.toggle("in-view", visibleSteps > 0);
  },
  { rootMargin: "-45% 0px -45% 0px", threshold: 0 }
);

steps.forEach((s) => observer.observe(s));
setLayer(0, "left");
const EMAILS = [
  {
    id: "e1",
    from: "security@paypa1-support.com",
    subject: "Your account will be locked in 1 hour!",
    preview: "We detected unusual activity. Click here to verify your identity immediately.",
    correct: ["lookalike-domain", "urgency", "generic-greeting"],
  },
  {
    id: "e2",
    from: "hr@yourcompany.com",
    subject: "Q3 salary revision — please review",
    preview: "Hi Alex, attached is your updated compensation letter. No action needed.",
    correct: [],
  },
  {
    id: "e3",
    from: "cfo@yourcompany-corp.co",
    subject: "Urgent wire — please process today",
    preview: "I'm in a meeting. Please wire $48,500 to the account in the attached PDF. Confidential.",
    correct: ["lookalike-domain", "urgency", "money-request", "authority-bias"],
  },
];

const TAGS = [
  { id: "lookalike-domain", label: "Lookalike domain" },
  { id: "urgency",          label: "Urgency / threat" },
  { id: "generic-greeting", label: "Generic greeting" },
  { id: "money-request",    label: "Money / wire request" },
  { id: "authority-bias",   label: "Authority pressure" },
  { id: "unexpected-attach",label: "Unexpected attachment" },
];

function renderTags() {
  const pool = document.getElementById("tags");
  pool.innerHTML = "";
  TAGS.forEach(t => {
    const el = document.createElement("div");
    el.className = "tag";
    el.draggable = true;
    el.dataset.tag = t.id;
    el.textContent = t.label;
    el.addEventListener("dragstart", e => e.dataTransfer.setData("text/plain", t.id));
    pool.appendChild(el);
  });
}

function renderInbox() {
  const inbox = document.getElementById("inbox");
  inbox.innerHTML = "";
  EMAILS.forEach(e => {
    const wrap = document.createElement("article");
    wrap.className = "email";
    wrap.dataset.emailId = e.id;
    wrap.innerHTML = `
      <h3>${e.subject}</h3>
      <div class="meta">From: ${e.from}</div>
      <p>${e.preview}</p>
      <div class="dropzone" data-zone="${e.id}"></div>
    `;
    const zone = wrap.querySelector(".dropzone");
    zone.addEventListener("dragover", ev => { ev.preventDefault(); zone.classList.add("over"); });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", ev => {
      ev.preventDefault();
      zone.classList.remove("over");
      const tagId = ev.dataTransfer.getData("text/plain");
      placeTag(e.id, tagId, zone);
    });
    inbox.appendChild(wrap);
  });
}

function placeTag(emailId, tagId, zone) {
  const email = EMAILS.find(x => x.id === emailId);
  if (zone.querySelector(`[data-tag="${tagId}"]`)) return;
  const tag = TAGS.find(t => t.id === tagId);
  const chip = document.createElement("span");
  chip.className = "tag tag-placed";
  chip.dataset.tag = tagId;
  chip.textContent = tag.label;
  const correct = email.correct.includes(tagId);
  chip.style.borderColor = correct ? "var(--ok)" : "var(--bad)";
  chip.style.color = correct ? "var(--ok)" : "var(--bad)";
  chip.addEventListener("click", () => chip.remove());
  zone.appendChild(chip);
  if (correct) zone.classList.add("ok"); else zone.classList.add("bad");
}

renderTags();
renderInbox();
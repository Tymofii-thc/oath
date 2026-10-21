/* Admin status page. Everything shown here is fetched live from the repo itself (raw CHANGELOG.md /
   THREAT-MODEL.md, and the commit list via the GitHub API) so there is exactly one copy of the truth
   to maintain: the repo. No build step, no server. All text goes through textContent, same discipline
   as the main site (fetched data is untrusted even though it's this project's own repo). */
(() => {
  'use strict';
  const RAW = 'https://raw.githubusercontent.com/Tymofii-thc/oath/main/';
  const API = 'https://api.github.com/repos/Tymofii-thc/oath/';
  const TIMEOUT_MS = 12000;

  async function fetchText(url) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      const r = await fetch(url, { signal: ctrl.signal, headers: url.startsWith(API) ? { accept: 'application/vnd.github+json' } : {} });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return url.startsWith(API) ? r.json() : r.text();
    } finally {
      clearTimeout(t);
    }
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.classList.remove('err');
  }
  function setError(id, label, e) {
    const el = document.getElementById(id);
    el.textContent = `could not load ${label}: ${e && e.message ? e.message : e}`;
    el.classList.add('err');
  }

  // Splits a markdown doc on "## " headers. Returns [{ title, body }], body excludes the header line.
  function sections(md) {
    const parts = md.split(/\n(?=## )/);
    return parts.filter((p) => p.startsWith('## ')).map((p) => {
      const nl = p.indexOf('\n');
      return { title: p.slice(3, nl === -1 ? undefined : nl).trim(), body: (nl === -1 ? '' : p.slice(nl + 1)).trim() };
    });
  }

  async function loadChangelog() {
    try {
      const md = await fetchText(RAW + 'CHANGELOG.md');
      const top = sections(md).slice(0, 2); // the current + previous version: enough to see what's new without scrolling a whole history
      setText('changelog', top.map((s) => `## ${s.title}\n${s.body}`).join('\n\n'));
    } catch (e) { setError('changelog', 'CHANGELOG.md', e); }
  }

  async function loadThreatModel() {
    let md;
    try { md = await fetchText(RAW + 'THREAT-MODEL.md'); }
    catch (e) { setError('not-covered', 'THREAT-MODEL.md', e); setError('found-in-review', 'THREAT-MODEL.md', e); return; }
    const secs = sections(md);
    const notCovered = secs.find((s) => s.title === 'Not covered');
    const foundInReview = secs.find((s) => s.title === 'Found in review');
    setText('not-covered', notCovered ? notCovered.body : 'section not found (THREAT-MODEL.md structure changed; see the file directly)');
    setText('found-in-review', foundInReview ? foundInReview.body : 'section not found (THREAT-MODEL.md structure changed; see the file directly)');
  }

  async function loadCommits() {
    try {
      const commits = await fetchText(API + 'commits?per_page=12&sha=main');
      const lines = commits.map((c) => {
        const date = (c.commit?.author?.date || '').slice(0, 10);
        const subject = (c.commit?.message || '').split('\n')[0];
        const sha = (c.sha || '').slice(0, 7);
        return `${date}  ${sha}  ${subject}`;
      });
      setText('commits', lines.join('\n'));
    } catch (e) { setError('commits', 'recent commits', e); }
  }

  loadChangelog();
  loadThreatModel();
  loadCommits();
})();

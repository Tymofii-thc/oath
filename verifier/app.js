/* Oath — live verifier. Vanilla ES2020, no build, no external requests except Solana JSON-RPC.
   All dynamic text goes through textContent / createTextNode (RPC data is untrusted). */
(() => {
  'use strict';

  /* ---------- constants ---------- */
  const DEFAULT_KEY = '5D4W8x8UeqW3qVi9uzNzvJPWiJZQaRWVR9ru2ckFhoih';
  const GOOD_DIGEST = 'sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc';
  const BAD_DIGEST = 'sha256:' + '1'.repeat(64);
  const NETS = {
    devnet: { rpc: 'https://api.devnet.solana.com', cluster: 'devnet' },
    mainnet: { rpc: 'https://solana-rpc.publicnode.com', cluster: 'mainnet-beta' }, // api.mainnet-beta.solana.com answers 403 to browser (Origin) requests
  };
  const SIG_LIMIT = 1000;
  const ROWS_SHOWN = 25;
  const RPC_TIMEOUT_MS = 20000;
  const B58_KEY = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  const B58_SIG = /^[1-9A-HJ-NP-Za-km-z]{60,100}$/;
  const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

  /* ---------- i18n ---------- */
  const I18N = {
    en: {
      skip: 'Skip to content',
      lang_label: 'Language',
      nav_label: 'Site',
      nav_verify: 'Verify',
      nav_how: 'How it works',
      tm: 'Threat model',
      hero_h1: "Don't deploy what the pipeline didn't build.",
      hero_p: 'Every CI build writes its image digest to Solana. Before deploy, oath verify or a Kubernetes webhook blocks any image with no record.',
      cta_run: 'Try the verifier',
      cta_docs: 'Set up in 3 steps',
      live_h: 'Verify an image',
      live_p: 'Runs in your browser. Same logic as the CLI.',
      f_signer: 'Signer public key',
      f_signer_ph: 'one or more, comma-separated',
      f_net: 'Network',
      f_digest: 'Image digest',
      presets: 'Try an example',
      p_good: 'A built image',
      p_bad: 'A swapped image',
      term_title: 'terminal',
      flow_h: 'How it works',
      st1_t: 'Build',
      st1_p: 'CI builds the image.',
      st2_t: 'Record',
      st2_p: 'Its digest goes to Solana, signed by the CI key.',
      st3_t: 'Verify',
      st3_p: 'Before deploy, oath verify or the webhook looks for a record.',
      details: 'Details',
      fmt_p: 'One Memo per build:',
      fmt_legend: 'version | image name | commit (12 chars) | image digest | time',
      out_ok: 'verified, the deploy proceeds',
      out_bad: 'no record, the deploy stops',
      int_h: 'Set up',
      int_p: 'Run oath init once to create the CI key. Then:',
      int_tabs: 'Integration',
      gh_p: 'Add SOLANA_SECRET_KEY as a secret and OATH_SIGNER (the public key) as a variable.',
      k8s_p: 'Checks every new Pod and fails closed. Start with mode=audit, then switch to enforce.',
      cli_p: 'Exit codes: 0 verified, 1 not verified, 2 error.',
      int_more: 'All options in the README →',
      int_approve: 'Need a second signer? Approve with your wallet →',
      copy: 'Copy',
      copied: 'Copied',
      rec_h: 'Signer records',
      rec_p: 'Newest first.',
      rec_load: 'Load records',
      c_time: 'Time',
      c_commit: 'Commit',
      c_image: 'Image',
      c_digest: 'Digest',
      c_tx: 'Transaction',
      rec_idle: 'No records loaded yet. Run a check or press Load records.',
      rec_loading: 'Loading records…',
      rec_none: 'No oath records found for this signer on {net}.',
      rec_err: 'Could not load records: {msg}',
      rec_count: 'Showing {n} of {total} records on {net}.',
      rec_row_verify: 'verify',
      rec_row_aria: 'Verify digest {d}',
      thr_h: 'Threat model',
      t_scn: 'Attack',
      t_res: 'Result',
      t_why: 'How',
      tag_blocked: 'Blocked',
      tag_limited: 'Limited',
      tag_mitigated: 'Mitigated',
      tag_closed: 'Fail closed',
      r1_s: 'Image swapped under the same tag',
      r1_w: 'The new digest has no record.',
      r2_s: 'Push or kubectl apply that bypasses CI',
      r2_w: 'oath verify exits 1; the webhook denies the Pod.',
      r3_s: 'Registry token leaked',
      r3_w: 'The attacker can push an image but cannot record its digest.',
      r4_s: 'Record made for a different image name',
      r4_w: 'Records are bound to the image name.',
      r5_s: 'Old, valid digest replayed',
      r5_w: 'Limit it with --max-age or oath revoke.',
      r6_s: 'CI key compromised, then revoked',
      r6_w: 'Remove it from the signer list: its records stop counting at once.',
      r7_s: 'Registry, RPC or webhook down',
      r7_w: 'New Pods are refused, running Pods are untouched. The CLI exits 2.',
      r8_s: 'Forged record that only mentions the signer',
      r8_w: 'Only transactions the signer actually signed count.',
      r9_s: "Running Pod's image edited, or debug container added",
      r9_w: 'The webhook checks updates and ephemeral containers too.',
      r10_s: 'Pods that were already running before install',
      r10_w: 'install.sh and Helm audit them at once and then every hour; a failed Job means an unverified or revoked image.',
      nc_h: 'Not covered',
      nc1_h: 'Stolen CI signing key.',
      nc1_p: 'Whoever holds it can record a forged digest. --quorum 2 adds a second approver key but is off by default. Rotation, revocation and --max-age limit the damage.',
      nc2_h: 'Malicious code built honestly.',
      nc2_p: 'The chain proves the signer recorded a digest, not that the code is safe. --attest checks which workflow built the image, not what is in it.',
      nc3_h: 'Mainnet in CI.',
      nc3_p: 'Supported, but CI has not run on live mainnet. devnet is the default and has no retention guarantee.',
      thr_more: 'Full threat model →',
      built: 'Built for Colosseum',
      license: 'MIT license',
      /* verifier states */
      chip_idle: 'idle',
      chip_run: 'running',
      idle_msg: 'Choose an example or press oath verify.',
      loading_msg: 'resolving signatures…',
      e_key_missing: 'Enter at least one signer public key.',
      e_key_bad: 'Does not look like a Solana public key (base58, 32–44 characters): {k}',
      e_digest: 'The digest must be sha256: followed by 64 hex characters.',
      a_signer_req: 'error: --signer is required',
      a_digest_req: 'error: --digest must be sha256:<64 hex characters>',
      ok_anchored: 'anchored at {t} by {s}',
      fail_expl: 'No record from the trusted signer for this digest.',
      fail_stat: 'scanned {tx} transactions, {rec} oath records',
      fail_limit: 'History is limited to the newest {n} transactions per signer.',
      fail_stop: 'Do not deploy this image.',
      err_rpc: 'could not query the Solana RPC ({net}): {msg}',
      err_hint: 'Public RPC endpoints are rate-limited. Retry in a moment or run the CLI with your own --rpc.',
      err_timeout: 'timed out after {s} s',
      err_http: 'HTTP {code}',
    },
    uk: {
      skip: 'Перейти до змісту',
      lang_label: 'Мова',
      nav_label: 'Сайт',
      nav_verify: 'Перевірка',
      nav_how: 'Як це працює',
      tm: 'Модель загроз',
      hero_h1: 'Не деплой того, чого не збирав пайплайн.',
      hero_p: 'Кожна збірка в CI записує digest образу в Solana. Перед деплоєм oath verify або webhook у Kubernetes блокує образ без запису.',
      cta_run: 'Спробувати верифікатор',
      cta_docs: 'Налаштувати за 3 кроки',
      live_h: 'Перевірити образ',
      live_p: 'Працює в браузері. Логіка та сама, що в CLI.',
      f_signer: 'Публічний ключ підписанта',
      f_signer_ph: 'один або кілька, через кому',
      f_net: 'Мережа',
      f_digest: 'Digest образу',
      presets: 'Спробуйте приклад',
      p_good: 'Зібраний образ',
      p_bad: 'Підмінений образ',
      term_title: 'термінал',
      flow_h: 'Як це працює',
      st1_t: 'Збірка',
      st1_p: 'CI збирає образ.',
      st2_t: 'Запис',
      st2_p: 'Його digest іде в Solana, підписаний ключем CI.',
      st3_t: 'Перевірка',
      st3_p: 'Перед деплоєм oath verify або webhook шукає запис.',
      details: 'Докладніше',
      fmt_p: 'Один Memo на збірку:',
      fmt_legend: 'версія | імʼя образу | коміт (12 символів) | digest образу | час',
      out_ok: 'перевірено, деплой іде',
      out_bad: 'запису нема, деплой зупинено',
      int_h: 'Налаштування',
      int_p: 'Один раз запустіть oath init, щоб створити ключ CI. Далі:',
      int_tabs: 'Інтеграція',
      gh_p: 'Додайте SOLANA_SECRET_KEY як секрет, а OATH_SIGNER (публічний ключ) як змінну.',
      k8s_p: 'Перевіряє кожен новий Pod і працює fail closed. Почніть з mode=audit, потім перейдіть на enforce.',
      cli_p: 'Коди виходу: 0 перевірено, 1 не перевірено, 2 помилка.',
      int_more: 'Усі опції в README →',
      int_approve: 'Потрібен другий підписант? Затвердіть гаманцем →',
      copy: 'Копіювати',
      copied: 'Скопійовано',
      rec_h: 'Записи підписанта',
      rec_p: 'Найновіші зверху.',
      rec_load: 'Завантажити записи',
      c_time: 'Час',
      c_commit: 'Коміт',
      c_image: 'Образ',
      c_digest: 'Digest',
      c_tx: 'Транзакція',
      rec_idle: 'Записи ще не завантажено. Запустіть перевірку або натисніть «Завантажити записи».',
      rec_loading: 'Завантажую записи…',
      rec_none: 'Записів oath для цього підписанта в {net} не знайдено.',
      rec_err: 'Не вдалося завантажити записи: {msg}',
      rec_count: 'Показано {n} із {total} записів у {net}.',
      rec_row_verify: 'перевірити',
      rec_row_aria: 'Перевірити digest {d}',
      thr_h: 'Модель загроз',
      t_scn: 'Атака',
      t_res: 'Результат',
      t_why: 'Як',
      tag_blocked: 'Заблоковано',
      tag_limited: 'Частково',
      tag_mitigated: 'Зменшено',
      tag_closed: 'Закрито',
      r1_s: 'Образ підмінено під тим самим тегом',
      r1_w: 'Для нового digest запису нема.',
      r2_s: 'Push або kubectl apply в обхід CI',
      r2_w: 'oath verify завершується з кодом 1; webhook відхиляє Pod.',
      r3_s: 'Токен реєстру витік',
      r3_w: 'Зловмисник може запушити образ, але не може записати його digest.',
      r4_s: 'Запис для іншого імені образу',
      r4_w: 'Записи привʼязані до імені образу.',
      r5_s: 'Повторне використання старого, але справжнього digest',
      r5_w: 'Обмежте через --max-age або oath revoke.',
      r6_s: 'Ключ CI скомпрометовано, потім відкликано',
      r6_w: 'Приберіть ключ зі списку підписантів: його записи одразу перестають діяти.',
      r7_s: 'Реєстр, RPC або webhook недоступні',
      r7_w: 'Нові Pod не проходять, працюючі не чіпаємо. CLI завершується з кодом 2.',
      r8_s: 'Підроблений запис, що лише згадує підписанта',
      r8_w: 'Враховуються лише транзакції, які підписант справді підписав.',
      r9_s: 'Змінили образ працюючого Pod або додали debug-контейнер',
      r9_w: 'Webhook перевіряє також оновлення та ephemeral-контейнери.',
      r10_s: 'Pod, що працювали ще до встановлення',
      r10_w: 'install.sh і Helm перевіряють їх одразу, а потім щогодини; Job із помилкою означає непідтверджений чи відкликаний образ.',
      nc_h: 'Не покрито',
      nc1_h: 'Вкрадений ключ підпису CI.',
      nc1_p: 'Хто його має, може записати фальшивий digest. --quorum 2 додає другий ключ затверджувача, але за замовчуванням вимкнений. Ротація, відкликання й --max-age зменшують шкоду.',
      nc2_h: 'Шкідливий код, зібраний чесно.',
      nc2_p: 'Блокчейн доводить, що підписант записав digest, а не що код безпечний. --attest перевіряє, який workflow зібрав образ, а не що в ньому.',
      nc3_h: 'Мейннет у CI.',
      nc3_p: 'Підтримується, але CI на живому мейннеті ще не проганявся. За замовчуванням devnet, без гарантій зберігання.',
      thr_more: 'Повна модель загроз →',
      built: 'Built for Colosseum',
      license: 'Ліцензія MIT',
      chip_idle: 'очікування',
      chip_run: 'виконується',
      idle_msg: 'Оберіть приклад або натисніть oath verify.',
      loading_msg: 'отримую підписи…',
      e_key_missing: 'Вкажіть хоча б один публічний ключ підписанта.',
      e_key_bad: 'Це не схоже на публічний ключ Solana (base58, 32–44 символи): {k}',
      e_digest: 'Digest має виглядати як sha256: і 64 шістнадцяткові символи.',
      a_signer_req: 'error: потрібен --signer',
      a_digest_req: 'error: --digest має бути sha256:<64 hex-символи>',
      ok_anchored: 'зафіксовано {t}, підписант {s}',
      fail_expl: 'Для цього digest нема запису від довіреного підписанта.',
      fail_stat: 'переглянуто транзакцій: {tx}, записів oath: {rec}',
      fail_limit: 'Історія обмежена {n} найновішими транзакціями на підписанта.',
      fail_stop: 'Не деплойте цей образ.',
      err_rpc: 'не вдалося опитати Solana RPC ({net}): {msg}',
      err_hint: 'Публічні RPC мають ліміти. Спробуйте за хвилину або запустіть CLI зі своїм --rpc.',
      err_timeout: 'час очікування вичерпано ({s} с)',
      err_http: 'HTTP {code}',
    },
  };

  /* ---------- state ---------- */
  const $ = (id) => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const state = {
    lang: 'en',
    seq: 0,
    result: { kind: 'idle' }, // last terminal result, re-rendered on language change
    records: null, // { net, rows: [...], status: 'idle'|'loading'|'ready'|'error', msg }
  };

  const el = {
    key: $('f-key'), net: $('f-net'), digest: $('f-digest'),
    eKey: $('e-key'), eDigest: $('e-digest'),
    form: $('vform'), btn: $('b-verify'),
    term: $('term'), chip: $('term-chip'), body: $('term-body'), out: $('out'),
    recBody: $('rec-body'), recStatus: $('rec-status'), recBtn: $('b-records'),
  };

  const t = (key, vars) => {
    const dict = I18N[state.lang] || I18N.en;
    let s = dict[key] ?? I18N.en[key] ?? key;
    if (vars) for (const k of Object.keys(vars)) s = s.split('{' + k + '}').join(String(vars[k]));
    return s;
  };

  /* ---------- helpers ---------- */
  const shortDigest = (d) => (d.length > 24 ? d.slice(0, 15) + '…' + d.slice(-6) : d);
  const shortKey = (k) => (k.length > 14 ? k.slice(0, 6) + '…' + k.slice(-4) : k);

  function fmtTime(s) {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return String(s).slice(0, 40);
    return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  const explorerUrl = (sig, net) =>
    'https://explorer.solana.com/tx/' + encodeURIComponent(sig) + '?cluster=' + NETS[net].cluster;

  function netOf(v) { return v === 'mainnet' ? 'mainnet' : 'devnet'; }

  /* ---------- Solana ---------- */
  async function rpcCall(net, method, rpcParams) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), RPC_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(NETS[net].rpc, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params: rpcParams }),
        signal: ctrl.signal,
      });
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error(t('err_timeout', { s: RPC_TIMEOUT_MS / 1000 }));
      throw new Error(e && e.message ? e.message : 'network error');
    } finally {
      clearTimeout(timer);
    }
    if (!res.ok) throw new Error(t('err_http', { code: res.status }));
    let json;
    try { json = await res.json(); } catch { throw new Error('invalid JSON from RPC'); }
    if (json.error) throw new Error(String(json.error.message || 'RPC error').slice(0, 200));
    return json.result;
  }

  /* memo: "[len] pod1|image|commit12|digest|ISO-time", several memos in one tx joined by "; " */
  function parseMemo(memo) {
    if (typeof memo !== 'string') return [];
    const out = [];
    for (const part of memo.split('; ')) {
      const body = part.replace(/^\[\d+\]\s*/, '');
      if (!body.startsWith('pod1|')) continue;
      const f = body.split('|');
      if (f.length < 5) continue;
      const digest = f[3].trim().toLowerCase();
      if (!DIGEST_RE.test(digest)) continue;
      out.push({ image: f[1], commit: f[2], digest, time: f.slice(4).join('|') });
    }
    return out;
  }

  /* getSignaturesForAddress also lists transactions that merely mention the address (anyone can add it as a read-only
     account next to a memo they signed themselves), so a record counts only if the signer really signed the transaction. */
  // a confirmed transaction never changes: ask once (the public devnet RPC allows ~10 getTransaction per 10 s per IP).
  // The answer also survives a reload in sessionStorage; storage may be blocked, then the in-memory cache still works.
  const signedCache = new Map();
  function stored(id, val) {
    try { if (val === undefined) { const v = sessionStorage.getItem('oath.sig.' + id); return v === null ? undefined : v === '1'; } sessionStorage.setItem('oath.sig.' + id, val ? '1' : '0'); } catch { /* ignore */ }
    return undefined;
  }
  function signedBy(net, key, sig) {
    const id = net + ':' + key + ':' + sig;
    if (!signedCache.has(id)) {
      const known = stored(id);
      const p = known !== undefined ? Promise.resolve(known) : signedByUncached(net, key, sig).then((v) => { stored(id, v); return v; });
      signedCache.set(id, p);
      p.catch(() => signedCache.delete(id));
    }
    return signedCache.get(id);
  }
  async function signedByUncached(net, key, sig) {
    const t = await rpcCall(net, 'getTransaction', [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]);
    const keys = (t && t.transaction && t.transaction.message && t.transaction.message.accountKeys) || [];
    return !!t && !(t.meta && t.meta.err) && keys.some((k) => k.pubkey === key && k.signer === true);
  }

  const SIGNED_CHECK_MAX = 8;  // records that get the signature check (public RPCs rate-limit); the digest being verified goes first
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function signedByRetry(net, key, sig) {
    for (let i = 0; ; i++) {
      try { return await signedBy(net, key, sig); }
      catch (e) { if (i >= 4 || !/429|rate|limit/i.test(String(e && e.message))) throw e; await sleep(1000 * (i + 1)); }
    }
  }

  async function verifyRest(net, results) {
    const todo = results.flatMap((r) => (r.rest || []).map((rec) => ({ key: r.key, rec })));
    const flags = new Array(todo.length).fill(false);
    let next = 0;
    const worker = async () => { for (let i = next++; i < todo.length; i = next++) flags[i] = await signedByRetry(net, todo[i].key, todo[i].rec.sig); };
    await Promise.all([worker(), worker(), worker()]); // a few at a time: one by one is slow, all at once trips the rate limit
    return todo.filter((_, i) => flags[i]).map((x) => x.rec);
  }

  async function fetchSigner(net, key, digest) {
    const sigs = await rpcCall(net, 'getSignaturesForAddress', [key, { limit: SIG_LIMIT }]);
    if (!Array.isArray(sigs)) throw new Error('unexpected RPC response');
    const records = [];
    let okTx = 0;
    for (const s of sigs) {
      if (!s || s.err) continue; // skip failed transactions
      okTx++;
      for (const r of parseMemo(s.memo)) {
        records.push({ ...r, signer: key, sig: String(s.signature || ''), blockTime: Number(s.blockTime) || 0 });
      }
    }
    // Verdict first: only the records for the digest being checked need the signature check, and those go in parallel.
    const mine = records.filter((r) => r.digest === digest).slice(0, 5);
    const flags = await Promise.all(mine.map((r) => signedByRetry(net, key, r.sig)));
    const verified = mine.filter((_, i) => flags[i]);
    const rest = records.filter((r) => r.digest !== digest).slice(0, SIGNED_CHECK_MAX); // for the table, checked afterwards
    return { key, total: sigs.length, okTx, records: verified, rest };
  }

  async function collect(net, keys, digest) {
    const settled = await Promise.allSettled(keys.map((k) => fetchSigner(net, k, digest)));
    const ok = [];
    let firstError = null;
    for (const s of settled) {
      if (s.status === 'fulfilled') ok.push(s.value);
      else if (!firstError) firstError = s.reason;
    }
    return { ok, firstError };
  }

  /* ---------- input ---------- */
  function readInput() {
    const rawKeys = el.key.value.split(/[\s,]+/).filter(Boolean);
    const digest = el.digest.value.trim().toLowerCase();
    return { keys: [...new Set(rawKeys)], digest, net: netOf(el.net.value) };
  }

  function validate() {
    const v = readInput();
    const errors = { key: '', digest: '' };
    if (v.keys.length === 0) errors.key = t('e_key_missing');
    else {
      const bad = v.keys.find((k) => !B58_KEY.test(k));
      if (bad) errors.key = t('e_key_bad', { k: bad.slice(0, 48) });
    }
    if (!DIGEST_RE.test(v.digest)) errors.digest = t('e_digest');
    v.errors = errors;
    v.ok = !errors.key && !errors.digest;
    return v;
  }

  function showFieldErrors(errors) {
    const set = (input, p, msg) => {
      p.textContent = msg;
      p.hidden = !msg;
      if (msg) input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
    };
    set(el.key, el.eKey, errors.key);
    set(el.digest, el.eDigest, errors.digest);
  }

  /* ---------- terminal rendering ---------- */
  function ln(parts) {
    const row = document.createElement('span');
    row.className = 'ln';
    for (const p of [].concat(parts)) {
      if (typeof p === 'string') row.appendChild(document.createTextNode(p));
      else row.appendChild(p);
    }
    return row;
  }
  const span = (cls, text) => {
    const s = document.createElement('span');
    s.className = cls;
    s.textContent = text;
    return s;
  };
  function cmdline(v) {
    const keys = v.keys && v.keys.length ? v.keys.join(',') : '<pubkey>';
    const dg = v.digest || 'sha256:…';
    return ln([span('prompt', '$ '), 'oath verify --signer ' + keys + ' --network ' + v.net + ' --digest ' + dg]);
  }

  function setTerm(stateName, chipText) {
    el.term.dataset.state = stateName;
    el.chip.textContent = chipText;
  }

  function renderTerminal(fresh) {
    const r = state.result;
    const frag = document.createDocumentFragment();
    let stateName = r.kind;
    let chip = '';

    if (r.kind === 'idle') {
      frag.appendChild(ln([span('prompt', '$ '), span('dim', t('idle_msg'))]));
      chip = t('chip_idle');
    } else if (r.kind === 'loading') {
      frag.appendChild(cmdline(r.v));
      frag.appendChild(ln(span('dim', t('loading_msg'))));
      chip = t('chip_run');
    } else if (r.kind === 'invalid') {
      frag.appendChild(cmdline(r.v));
      if (r.v.errors.key) frag.appendChild(ln(span('warnc', r.v.keys.length === 0 ? t('a_signer_req') : 'error: ' + r.v.errors.key)));
      if (r.v.errors.digest) frag.appendChild(ln(span('warnc', t('a_digest_req'))));
      frag.appendChild(ln(span('dim', 'exit code: 2')));
      stateName = 'error';
      chip = 'exit 2';
    } else if (r.kind === 'ok') {
      const m = r.match;
      frag.appendChild(cmdline(r.v));
      frag.appendChild(ln(span('good verdict', 'VERIFIED')));
      frag.appendChild(ln('commit: ' + m.commit + ' (' + m.image + ')'));
      frag.appendChild(ln(t('ok_anchored', { t: m.time, s: m.signer })));
      if (B58_SIG.test(m.sig)) {
        const a = document.createElement('a');
        a.href = explorerUrl(m.sig, r.v.net);
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = explorerUrl(m.sig, r.v.net);
        frag.appendChild(ln(['tx: ', a]));
      }
      frag.appendChild(ln(span('good', 'exit code: 0')));
      chip = 'exit 0';
    } else if (r.kind === 'fail') {
      frag.appendChild(cmdline(r.v));
      frag.appendChild(ln(span('badc verdict', 'NOT VERIFIED')));
      frag.appendChild(ln(t('fail_expl')));
      frag.appendChild(ln(span('dim', t('fail_stat', { tx: r.stats.tx, rec: r.stats.rec }))));
      if (r.stats.limited) frag.appendChild(ln(span('dim', t('fail_limit', { n: SIG_LIMIT }))));
      frag.appendChild(ln(t('fail_stop')));
      frag.appendChild(ln(span('badc', 'exit code: 1')));
      chip = 'exit 1';
    } else if (r.kind === 'error') {
      frag.appendChild(cmdline(r.v));
      frag.appendChild(ln([span('warnc', 'ERROR'), ' ' + t('err_rpc', { net: r.v.net, msg: r.msg })]));
      frag.appendChild(ln(span('dim', t('err_hint'))));
      frag.appendChild(ln(span('warnc', 'exit code: 2')));
      chip = 'exit 2';
    }

    const pre = document.createElement('pre');
    pre.id = 'out';
    if (fresh && (r.kind === 'ok' || r.kind === 'fail' || r.kind === 'error' || r.kind === 'invalid')) pre.className = 'fresh';
    pre.appendChild(frag);
    el.body.replaceChildren(pre);
    el.out = pre;
    el.body.setAttribute('aria-busy', r.kind === 'loading' ? 'true' : 'false');
    setTerm(stateName, chip);
  }

  /* ---------- records table ---------- */
  function renderRecords() {
    const rs = state.records;
    const body = el.recBody;
    body.replaceChildren();

    const emptyRow = (msg) => {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5;
      td.className = 'empty';
      td.textContent = msg;
      tr.appendChild(td);
      body.appendChild(tr);
    };

    if (!rs || rs.status === 'idle') { emptyRow(t('rec_idle')); el.recStatus.textContent = ''; return; }
    if (rs.status === 'loading') { emptyRow(t('rec_loading')); el.recStatus.textContent = t('rec_loading'); return; }
    if (rs.status === 'error') { emptyRow(t('rec_err', { msg: rs.msg })); el.recStatus.textContent = t('rec_err', { msg: rs.msg }); return; }
    if (rs.rows.length === 0) {
      const m = t('rec_none', { net: rs.net });
      emptyRow(m);
      el.recStatus.textContent = m;
      return;
    }

    const shown = rs.rows.slice(0, ROWS_SHOWN);
    for (const r of shown) {
      const tr = document.createElement('tr');
      const cell = (text, title) => {
        const td = document.createElement('td');
        td.textContent = text;
        if (title) td.title = title;
        tr.appendChild(td);
        return td;
      };
      cell(fmtTime(r.time || ''), r.time);
      cell(r.commit);
      cell(r.image);
      const dtd = cell(shortDigest(r.digest), r.digest);
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'row-btn';
      b.textContent = t('rec_row_verify');
      b.setAttribute('aria-label', t('rec_row_aria', { d: shortDigest(r.digest) }));
      b.addEventListener('click', () => {
        el.digest.value = r.digest;
        el.key.value = r.signer;
        el.net.value = rs.net;
        document.getElementById('verify').scrollIntoView({ block: 'start' });
        runVerify();
      });
      dtd.appendChild(b);
      const txtd = document.createElement('td');
      if (B58_SIG.test(r.sig)) {
        const a = document.createElement('a');
        a.href = explorerUrl(r.sig, rs.net);
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.textContent = r.sig.slice(0, 8) + '…' + r.sig.slice(-4) + ' ↗';
        txtd.appendChild(a);
      } else txtd.textContent = '—';
      tr.appendChild(txtd);
      body.appendChild(tr);
    }
    el.recStatus.textContent = t('rec_count', { n: shown.length, total: rs.rows.length, net: rs.net });
  }

  function sortedRecords(okResults) {
    const rows = [];
    for (const r of okResults) rows.push(...r.records);
    const seen = new Set();
    const uniq = rows.filter((r) => {
      const id = r.sig + '|' + r.digest;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
    uniq.sort((a, b) => b.blockTime - a.blockTime);
    return uniq;
  }

  /* ---------- actions ---------- */
  function syncUrl(v) {
    try {
      const q = new URLSearchParams();
      q.set('key', v.keys.join(','));
      q.set('digest', v.digest);
      q.set('net', v.net);
      q.set('lang', state.lang);
      history.replaceState(null, '', '?' + q.toString() + location.hash);
    } catch { /* file:// and sandboxed frames may refuse; not important */ }
  }

  function setBusy(busy) {
    el.btn.disabled = busy;
    el.btn.setAttribute('aria-disabled', busy ? 'true' : 'false');
  }

  async function runVerify() {
    const v = validate();
    showFieldErrors(v.errors);
    if (!v.ok) {
      state.result = { kind: 'invalid', v };
      renderTerminal(true);
      (v.errors.key ? el.key : el.digest).focus();
      return;
    }
    const seq = ++state.seq;
    setBusy(true);
    syncUrl(v);
    state.result = { kind: 'loading', v };
    renderTerminal(false);
    state.records = { net: v.net, rows: [], status: 'loading' };
    renderRecords();

    let res;
    try {
      res = await collect(v.net, v.keys, v.digest);
    } catch (e) {
      res = { ok: [], firstError: e };
    }
    if (seq !== state.seq) return; // a newer run superseded this one
    setBusy(false);

    const rows = sortedRecords(res.ok);
    state.records = { net: v.net, rows, status: res.ok.length ? 'ready' : 'error', msg: res.firstError ? res.firstError.message : '' };
    renderRecords();

    const match = rows.find((r) => r.digest === v.digest);
    if (match) {
      state.result = { kind: 'ok', v, match };
    } else if (res.firstError) {
      state.result = { kind: 'error', v, msg: res.firstError.message || 'unknown error' };
    } else {
      state.result = {
        kind: 'fail', v,
        stats: {
          tx: res.ok.reduce((n, r) => n + r.okTx, 0),
          rec: rows.length,
          limited: res.ok.some((r) => r.total >= SIG_LIMIT),
        },
      };
    }
    renderTerminal(true);
  }

  async function loadRecords() {
    const v = validate();
    showFieldErrors({ key: v.errors.key, digest: '' });
    if (v.errors.key) { el.key.focus(); return; }
    const seq = ++state.seq;
    state.records = { net: v.net, rows: [], status: 'loading' };
    renderRecords();
    const res = await collect(v.net, v.keys, v.digest);
    if (seq !== state.seq) return;
    if (res.ok.length === 0) state.records = { net: v.net, rows: [], status: 'error', msg: res.firstError ? res.firstError.message : 'unknown error' };
    else {
      const extra = await verifyRest(v.net, res.ok).catch(() => []);
      if (seq !== state.seq) return;
      state.records = { net: v.net, rows: sortedRecords([{ records: [...res.ok.flatMap((r) => r.records), ...extra] }]), status: 'ready' };
    }
    renderRecords();
  }

  function preset(kind) {
    if (kind === 'good') {
      el.key.value = DEFAULT_KEY;
      el.net.value = 'devnet';
      el.digest.value = GOOD_DIGEST;
    } else {
      if (!el.key.value.trim()) el.key.value = DEFAULT_KEY;
      el.digest.value = BAD_DIGEST;
    }
    runVerify();
  }

  /* ---------- language ---------- */
  function detectLang() {
    const q = (params.get('lang') || '').toLowerCase();
    if (q === 'uk' || q === 'en') return q;
    return (navigator.language || 'en').toLowerCase().startsWith('uk') ? 'uk' : 'en';
  }

  function applyLang(lang) {
    state.lang = lang;
    document.documentElement.lang = lang;
    document.title = lang === 'uk' ? 'Oath — proof of deploy (докази деплою)' : 'Oath — proof of deploy';
    for (const n of document.querySelectorAll('[data-i18n]')) n.textContent = t(n.dataset.i18n);
    for (const n of document.querySelectorAll('[data-i18n-attr]')) {
      for (const pair of n.dataset.i18nAttr.split(',')) {
        const [attr, key] = pair.split(':');
        n.setAttribute(attr.trim(), t(key.trim()));
      }
    }
    for (const b of document.querySelectorAll('.lang [data-lang]')) b.setAttribute('aria-pressed', b.dataset.lang === lang ? 'true' : 'false');
    // links to other pages of the site keep the chosen language
    for (const a of document.querySelectorAll('a[data-keep-lang]')) a.setAttribute('href', a.dataset.keepLang + '?lang=' + lang);
    // validation messages and dynamic blocks follow the language
    if (!el.eKey.hidden || !el.eDigest.hidden) showFieldErrors(validate().errors);
    renderTerminal(false);
    renderRecords();
    try {
      const q = new URLSearchParams(location.search);
      q.set('lang', lang);
      history.replaceState(null, '', '?' + q.toString() + location.hash);
    } catch { /* ignore */ }
  }

  /* ---------- tabs ---------- */
  function initTabs() {
    const tabs = [...document.querySelectorAll('[role="tab"]')];
    const select = (tab, focus) => {
      for (const x of tabs) {
        const on = x === tab;
        x.setAttribute('aria-selected', on ? 'true' : 'false');
        x.tabIndex = on ? 0 : -1;
        document.getElementById(x.getAttribute('aria-controls')).hidden = !on;
      }
      if (focus) tab.focus();
    };
    for (const tab of tabs) {
      tab.addEventListener('click', () => select(tab, false));
      tab.addEventListener('keydown', (e) => {
        const i = tabs.indexOf(tab);
        let n = -1;
        if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
        else if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
        else if (e.key === 'Home') n = 0;
        else if (e.key === 'End') n = tabs.length - 1;
        if (n >= 0) { e.preventDefault(); select(tabs[n], true); }
      });
    }
  }

  /* ---------- copy ---------- */
  function initCopy() {
    for (const btn of document.querySelectorAll('.copy')) {
      btn.addEventListener('click', async () => {
        const src = document.getElementById(btn.dataset.copy);
        const text = src ? src.textContent : '';
        let ok = false;
        try {
          await navigator.clipboard.writeText(text);
          ok = true;
        } catch {
          const ta = document.createElement('textarea');
          ta.value = text;
          ta.setAttribute('readonly', '');
          ta.className = 'sr-only';
          document.body.appendChild(ta);
          ta.select();
          try { ok = document.execCommand('copy'); } catch { ok = false; }
          ta.remove();
        }
        if (ok) {
          btn.textContent = t('copied');
          setTimeout(() => { btn.textContent = t('copy'); }, 1600);
        }
      });
    }
  }

  /* ---------- init ---------- */
  function init() {
    const qKey = params.get('key');
    const qDigest = params.get('digest');
    const qNet = params.get('net');
    el.key.value = qKey ? qKey : DEFAULT_KEY;
    el.digest.value = qDigest ? qDigest : GOOD_DIGEST;
    el.net.value = qNet === 'mainnet' ? 'mainnet' : 'devnet';

    for (const b of document.querySelectorAll('.lang [data-lang]')) b.addEventListener('click', () => applyLang(b.dataset.lang));

    el.form.addEventListener('submit', (e) => { e.preventDefault(); runVerify(); });
    $('p-good').addEventListener('click', () => preset('good'));
    $('p-bad').addEventListener('click', () => preset('bad'));
    el.recBtn.addEventListener('click', loadRecords);
    $('cta-run').addEventListener('click', () => {
      document.getElementById('verify').scrollIntoView({ block: 'start' });
      preset('good');
    });
    for (const input of [el.key, el.digest]) {
      input.addEventListener('input', () => {
        if (input.getAttribute('aria-invalid') === 'true') showFieldErrors(validate().errors);
      });
    }

    initTabs();
    initCopy();
    applyLang(detectLang());

    // key + digest in the URL: start the check automatically
    if (qKey && qDigest) runVerify();
  }

  init();
})();

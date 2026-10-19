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
      tagline: 'proof of deploy',
      lang_label: 'Language',
      hero_h1: "Don't deploy what the pipeline didn't build.",
      hero_p: 'Oath stops an image from reaching production unless your own pipeline built it. Every CI build records commit → digest → time in Solana, as a standard Memo transaction signed by the CI key. Before deploy, oath verify checks the image digest against those records and blocks the deploy if there is none.',
      cta_run: 'Run live check',
      cta_docs: 'Integrate in 3 steps',
      fact1: 'Standard Memo program, no custom smart contract',
      fact2: 'CLI and Kubernetes admission webhook',
      fact3: 'devnet by default, mainnet supported',
      flow_h: 'How it works',
      s1_sub: 'source revision',
      s2_sub: 'image digest',
      s3_sub: 'signed by the CI key',
      s4_sub: 'oath verify · admission webhook',
      out_ok: 'verified, the deploy proceeds',
      out_bad: 'no record, the deploy is stopped',
      fmt_h: 'Record format',
      fmt_p: 'One Memo per build, fields separated by a vertical bar:',
      fmt_legend: 'version | image name (the record is bound to it) | first 12 characters of the commit | image digest | ISO time',
      live_h: 'Live verifier',
      live_p: 'Runs in your browser: it queries the Solana RPC directly with the same logic as the CLI.',
      f_signer: 'Signer (public key, comma-separated)',
      f_net: 'Network',
      f_digest: 'Image digest',
      presets: 'One-click demo',
      p_good: 'known-good digest',
      p_bad: 'tampered digest',
      term_title: 'terminal output',
      int_h: 'Integrate',
      int_p: 'Three steps: create a CI key, anchor after the build, verify before the deploy.',
      int_tabs: 'Integration',
      gh_p: 'Run oath init once, then add the secret SOLANA_SECRET_KEY and the variable OATH_SIGNER (the public key) to the repository. If the public devnet faucet refuses, oath init waits while you fund the key at faucet.solana.com.',
      cli_p: 'Exit codes: 0 verified, 1 not verified, 2 error (network, arguments).',
      k8s_p: 'The webhook checks every new Pod, so kubectl apply cannot bypass the pipeline. It fails closed: if the registry, the RPC or the webhook is unreachable, new Pods are not admitted. Start with OATH_MODE=audit.',
      copy: 'Copy',
      copied: 'Copied',
      rec_h: 'Signer records',
      rec_p: 'Pipeline records anchored by the signer above, newest first.',
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
      t_scn: 'Scenario',
      t_res: 'Result',
      t_why: 'Why',
      tag_blocked: 'Blocked',
      tag_limited: 'Limited',
      tag_mitigated: 'Mitigated',
      tag_closed: 'Fail closed',
      r1_s: 'Image swapped in the registry under the same tag',
      r1_w: 'The pulled digest has no record from a trusted signer.',
      r2_s: 'Manual docker push or kubectl apply, bypassing CI',
      r2_w: 'oath verify exits with 1; the admission webhook denies the Pod.',
      r3_s: 'Registry token leaked, CI signing key safe',
      r3_w: 'The attacker can push an image but cannot anchor its digest.',
      r4_s: 'Record anchored for a different image name',
      r4_w: 'Records are bound to the image name (disable with --no-bind).',
      r5_s: 'Old but legitimate digest replayed',
      r5_w: 'Use --max-age to reject old records; without it the digest passes.',
      r6_s: 'CI key compromised, then revoked',
      r6_w: 'Remove the key from the signer list: its records stop counting at once. A forged record you notice later can be marked with a signed revocation (oath revoke).',
      r7_s: 'Registry, RPC or webhook unreachable',
      r7_w: 'New Pods are not admitted, running Pods are untouched. The CLI exits with 2.',
      nc_h: 'Not covered',
      nc1_h: 'Stolen CI signing key.',
      nc1_p: 'Whoever holds SOLANA_SECRET_KEY can anchor a forged digest. With --quorum 2 a second, independent approver key is also required (it can sign from a browser wallet on the approve page), but that needs a human in the loop and is off by default. Rotation, revocation of keys and digests, --max-age and image binding limit the damage further. The wallet flow was tested with a stand-in wallet, not with a real Ledger.',
      nc2_h: 'Malicious code built honestly.',
      nc2_p: 'The chain proves that the signer recorded a digest, not that the code is safe. --attest additionally verifies a Sigstore-signed SLSA build attestation (which workflow built the image); it does not judge the code. CI also publishes a signed SBOM. The optional Trivy scan checks fixable CRITICAL vulnerabilities by default.',
      nc3_h: 'Mainnet in CI.',
      nc3_p: 'Mainnet is supported, but CI has not been run on live mainnet yet. devnet is the default and has no retention guarantees.',
      nc4_h: 'Availability and existing Pods.',
      nc4_p: 'With failurePolicy: Fail, registry or RPC outages block new Pods, except images verified within the last hour (Ignore is also available). Several RPC endpoints can be listed for failover. Pods created before the webhook was installed are checked by an optional audit CronJob or by running oath audit.',
      built: 'Built for Colosseum',
      license: 'MIT license',
      /* verifier states */
      chip_idle: 'idle',
      chip_run: 'running',
      idle_msg: 'Choose a preset or press oath verify.',
      loading_msg: 'resolving signatures…',
      e_key_missing: 'Enter at least one signer public key.',
      e_key_bad: 'Does not look like a Solana public key (base58, 32–44 characters): {k}',
      e_digest: 'The digest must be sha256: followed by 64 hex characters.',
      a_signer_req: 'error: --signer is required',
      a_digest_req: 'error: --digest must be sha256:<64 hex characters>',
      ok_anchored: 'anchored at {t} by {s}',
      fail_expl: 'No pipeline build from the trusted signer is anchored for this digest.',
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
      tagline: 'proof of deploy',
      lang_label: 'Мова',
      hero_h1: 'Не деплой того, чого не збирав пайплайн.',
      hero_p: 'Oath не пускає в прод образ, який не збирав ваш пайплайн. Кожна збірка в CI записує в Solana коміт → digest → час (звичайна Memo-транзакція, підписана ключем CI). Перед деплоєм oath verify звіряє digest образу з цими записами й блокує деплой, якщо запису нема.',
      cta_run: 'Запустити живу перевірку',
      cta_docs: 'Підключити за 3 кроки',
      fact1: 'Стандартна Memo-програма, власного смарт-контракту нема',
      fact2: 'CLI і Kubernetes admission webhook',
      fact3: 'за замовчуванням devnet, мейннет підтримується',
      flow_h: 'Як це працює',
      s1_sub: 'версія коду',
      s2_sub: 'digest образу',
      s3_sub: 'підпис ключем CI',
      s4_sub: 'oath verify · admission webhook',
      out_ok: 'перевірено, деплой іде',
      out_bad: 'запису нема, деплой зупинено',
      fmt_h: 'Формат запису',
      fmt_p: 'Один Memo на збірку, поля розділені вертикальною рискою:',
      fmt_legend: 'версія | імʼя образу (запис привʼязаний до нього) | перші 12 символів коміту | digest образу | час ISO',
      live_h: 'Живий верифікатор',
      live_p: 'Працює у вашому браузері: напряму питає Solana RPC, логіка та сама, що й у CLI.',
      f_signer: 'Підписант (публічний ключ, через кому)',
      f_net: 'Мережа',
      f_digest: 'Digest образу',
      presets: 'Демо в один клік',
      p_good: 'справжній digest',
      p_bad: 'підроблений digest',
      term_title: 'вивід термінала',
      int_h: 'Підключення',
      int_p: 'Три кроки: ключ CI, запис після збірки, перевірка перед деплоєм.',
      int_tabs: 'Інтеграція',
      gh_p: 'Один раз запустіть oath init, потім додайте в репозиторій секрет SOLANA_SECRET_KEY і змінну OATH_SIGNER (публічний ключ). Якщо публічний devnet-faucet відмовляє, oath init чекає, поки ви поповните ключ на faucet.solana.com.',
      cli_p: 'Коди виходу: 0 перевірено, 1 не перевірено, 2 помилка (мережа, аргументи).',
      k8s_p: 'Webhook перевіряє кожен новий Pod, тож kubectl apply не обійде пайплайн. Він fail closed: якщо реєстр, RPC або сам webhook недоступні, нові Pod не проходять. Почніть з OATH_MODE=audit.',
      copy: 'Копіювати',
      copied: 'Скопійовано',
      rec_h: 'Записи підписанта',
      rec_p: 'Записи пайплайна, зафіксовані підписантом вище, найновіші зверху.',
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
      t_scn: 'Сценарій',
      t_res: 'Результат',
      t_why: 'Чому',
      tag_blocked: 'Заблоковано',
      tag_limited: 'Частково',
      tag_mitigated: 'Зменшено',
      tag_closed: 'Fail closed',
      r1_s: 'Образ у реєстрі підмінено під тим самим тегом',
      r1_w: 'Для витягнутого digest нема запису від довіреного підписанта.',
      r2_s: 'Ручний docker push або kubectl apply в обхід CI',
      r2_w: 'oath verify завершується з кодом 1; admission webhook відхиляє Pod.',
      r3_s: 'Токен реєстру витік, ключ підпису CI цілий',
      r3_w: 'Зловмисник може запушити образ, але не може записати його digest.',
      r4_s: 'Запис зафіксовано для іншого імені образу',
      r4_w: 'Записи привʼязані до імені образу (вимикається через --no-bind).',
      r5_s: 'Повторне використання старого, але справжнього digest',
      r5_w: 'Прапорець --max-age відхиляє старі записи; без нього digest проходить.',
      r6_s: 'Ключ CI скомпрометовано, потім відкликано',
      r6_w: 'Приберіть ключ зі списку підписантів: його записи перестають діяти одразу. Фальшивий запис, який помітили пізніше, можна позначити підписаним відкликанням (oath revoke).',
      r7_s: 'Реєстр, RPC або webhook недоступні',
      r7_w: 'Нові Pod не проходять, працюючі не чіпаємо. CLI завершується з кодом 2.',
      nc_h: 'Не покрито',
      nc1_h: 'Вкрадений ключ підпису CI.',
      nc1_p: 'Хто має SOLANA_SECRET_KEY, може записати фальшивий digest. З --quorum 2 додатково потрібен другий, незалежний ключ затверджувача (він може підписувати з браузерного кошилька на сторінці approve), але для цього потрібна людина в процесі, і за замовчуванням це вимкнено. Ротація, відкликання ключів і digest, --max-age і привʼязка до образу зменшують шкоду далі. Потік через кошилька перевірено на підставному кошильку, а не на справжньому Ledger.',
      nc2_h: 'Шкідливий код, зібраний чесно.',
      nc2_p: 'Блокчейн доводить, що підписант зафіксував digest, а не що код безпечний. --attest додатково перевіряє підписану через Sigstore SLSA-атестацію збірки (який workflow зібрав образ); код вона не оцінює. CI також публікує підписаний SBOM. Необовʼязкове сканування Trivy за замовчуванням перевіряє виправні CRITICAL-вразливості.',
      nc3_h: 'Мейннет у CI.',
      nc3_p: 'Мейннет підтримується, але CI на живому мейннеті ще не проганявся. За замовчуванням devnet, без гарантій зберігання.',
      nc4_h: 'Доступність і наявні Pod.',
      nc4_p: 'При failurePolicy: Fail недоступність реєстру чи RPC блокує нові Pod, окрім образів, перевірених за останню годину (є й варіант Ignore). Можна вказати кілька RPC для перемикання. Pod, створені до встановлення webhook, перевіряє необовʼязковий CronJob-аудит або ручний oath audit.',
      built: 'Built for Colosseum',
      license: 'Ліцензія MIT',
      chip_idle: 'очікування',
      chip_run: 'виконується',
      idle_msg: 'Оберіть пресет або натисніть oath verify.',
      loading_msg: 'отримую підписи…',
      e_key_missing: 'Вкажіть хоча б один публічний ключ підписанта.',
      e_key_bad: 'Це не схоже на публічний ключ Solana (base58, 32–44 символи): {k}',
      e_digest: 'Digest має виглядати як sha256: і 64 шістнадцяткові символи.',
      a_signer_req: 'error: потрібен --signer',
      a_digest_req: 'error: --digest має бути sha256:<64 hex-символи>',
      ok_anchored: 'зафіксовано {t}, підписант {s}',
      fail_expl: 'Для цього digest нема запису збірки від довіреного підписанта.',
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
  async function signedBy(net, key, sig) {
    const t = await rpcCall(net, 'getTransaction', [sig, { encoding: 'jsonParsed', maxSupportedTransactionVersion: 0, commitment: 'confirmed' }]);
    const keys = (t && t.transaction && t.transaction.message && t.transaction.message.accountKeys) || [];
    return !!t && !(t.meta && t.meta.err) && keys.some((k) => k.pubkey === key && k.signer === true);
  }

  const SIGNED_CHECK_MAX = 8;  // records that get the signature check (public RPCs rate-limit); the digest being verified goes first
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function signedByRetry(net, key, sig) {
    for (let i = 0; ; i++) {
      try { return await signedBy(net, key, sig); }
      catch (e) { if (i >= 4 || !/429|rate|limit/i.test(String(e && e.message))) throw e; await sleep(2000 * (i + 1)); }
    }
  }

  async function verifyRest(net, results) {
    const out = [];
    for (const r of results) for (const rec of r.rest || []) if (await signedByRetry(net, r.key, rec.sig)) out.push(rec);
    return out;
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
      frag.appendChild(ln([span('good', 'VERIFIED'), ' ' + r.v.digest]));
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
      frag.appendChild(ln([span('badc', 'NOT VERIFIED'), ' ' + r.v.digest]));
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

    // the table gets the other records once their signatures are checked (does not delay the verdict)
    verifyRest(v.net, res.ok).then((extra) => {
      if (seq !== state.seq || !extra.length) return;
      state.records = { ...state.records, rows: sortedRecords([{ records: [...rows, ...extra] }]) };
      renderRecords();
    }).catch(() => {});
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

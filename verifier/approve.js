/* oath approve: a second signature (or a revocation) from a browser wallet. Vanilla ES2020; needs only the vendored @solana/web3.js.
   The page builds one Memo transaction and asks the wallet to sign it. Text from inputs goes through textContent only. */
(() => {
  'use strict';
  const NETS = {
    devnet: { rpc: 'https://api.devnet.solana.com', cluster: 'devnet' },
    mainnet: { rpc: 'https://solana-rpc.publicnode.com', cluster: 'mainnet-beta' },
  };
  const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
  const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
  const $ = (id) => document.getElementById(id);
  let provider = null;
  let wallet = null; // PublicKey

  /* ---------- i18n ---------- */
  const I18N = {
    en: {
      skip: 'Skip to content',
      lang_label: 'Language',
      nav_label: 'Site',
      nav_verify: 'Verify',
      brand_back: 'oath, back to the main page',
      ap_h1: 'Approve a build or revoke a digest with your wallet',
      ap_lead: 'Sign one Memo transaction as the second signer (--quorum 2). Your private key never leaves the wallet. Tested with Phantom and Solflare; other wallets are untested.',
      ap_warn: 'Compare the digest with the CI log of the build you approve. An unchecked approval defeats the purpose.',
      ap_connect: 'Connect wallet',
      ap_wallet_other: 'Other wallet',
      ap_not_connected: 'not connected',
      ap_mode: 'Action',
      ap_mode_approve: 'Approve a build',
      ap_mode_revoke: 'Revoke a digest',
      ap_mode_msg_approve: 'Approve a release (signed message)',
      ap_mode_msg_revoke: 'Revoke (signed message)',
      ap_days: 'Valid for (days)',
      ap_msg_l: 'Message to sign (the wallet shows this text)',
      ap_json_l: 'Signed statement (a file; nothing was sent anywhere)',
      ap_dl: 'Download',
      ap_cp: 'Copy',
      ap_signed: 'Signed by {w}. No transaction was sent and no network was used.',
      ap_when: '(time of signing)',
      ap_e_days: 'Valid for 1 to 366 days.',
      ap_net: 'Network',
      ap_image: 'Image name',
      ap_commit: 'Commit',
      ap_digest: 'Image digest',
      ap_reason: 'Reason',
      ap_reason_ph: 'why this digest is bad',
      ap_preview_l: 'Memo to sign',
      ap_sign: 'Sign with wallet',
      ap_result: 'result',
      ap_idle: 'Connect a wallet, check the memo, then sign.',
      ap_fill: '(fill in the fields)',
      ap_time: '<time of signing>',
      ap_e_digest: 'The digest must look like sha256:<64 hex characters>.',
      ap_e_image: 'Enter the image name (for example ghcr.io/owner/app).',
      ap_e_commit: 'The commit must be 7-40 hex characters.',
      ap_nowallet: 'No Solana wallet found in this browser. Install Phantom or Solflare and reload.',
      ap_refused: 'Wallet connection was refused: {msg}',
      ap_waiting: 'Waiting for your wallet to sign…',
      ap_sending: 'Sending…',
      ap_done_approve: 'Approved. Signed by {w}',
      ap_done_revoke: 'Revoked. Signed by {w}',
      ap_hint_approve: 'Verify with both signers: oath verify --signer {ci},{w} --quorum 2 --digest {d}',
      ap_hint_revoke: 'oath verify now reports this digest as REVOKED.',
      ap_view_tx: 'View the transaction in Solana Explorer',
      ap_fail: 'Not signed or not sent: {msg}',
    },
    uk: {
      skip: 'Перейти до змісту',
      lang_label: 'Мова',
      nav_label: 'Сайт',
      nav_verify: 'Перевірка',
      brand_back: 'oath, назад на головну сторінку',
      ap_h1: 'Затвердіть збірку або відкличте digest своїм гаманцем',
      ap_lead: 'Підпишіть одну Memo-транзакцію як другий підписант (--quorum 2). Приватний ключ не залишає гаманець. Перевірено з Phantom і Solflare; інші гаманці не перевірялися.',
      ap_warn: 'Звірте digest із журналом CI збірки, яку затверджуєте. Затвердження без перевірки втрачає сенс.',
      ap_connect: 'Підключити гаманець',
      ap_wallet_other: 'Інший гаманець',
      ap_not_connected: 'не підключено',
      ap_mode: 'Дія',
      ap_mode_approve: 'Затвердити збірку',
      ap_mode_revoke: 'Відкликати digest',
      ap_mode_msg_approve: 'Схвалити реліз (підписане повідомлення)',
      ap_mode_msg_revoke: 'Відкликати (підписане повідомлення)',
      ap_days: 'Діє (днів)',
      ap_msg_l: 'Повідомлення для підпису (гаманець покаже цей текст)',
      ap_json_l: 'Підписана заява (файл; нічого нікуди не надіслано)',
      ap_dl: 'Завантажити',
      ap_cp: 'Копіювати',
      ap_signed: 'Підписано {w}. Транзакцію не надсилано, мережа не використовувалась.',
      ap_when: '(час підпису)',
      ap_e_days: 'Діє від 1 до 366 днів.',
      ap_net: 'Мережа',
      ap_image: 'Імʼя образу',
      ap_commit: 'Коміт',
      ap_digest: 'Digest образу',
      ap_reason: 'Причина',
      ap_reason_ph: 'чому цей digest поганий',
      ap_preview_l: 'Memo для підпису',
      ap_sign: 'Підписати гаманцем',
      ap_result: 'результат',
      ap_idle: 'Підключіть гаманець, перевірте memo і підпишіть.',
      ap_fill: '(заповніть поля)',
      ap_time: '<час підпису>',
      ap_e_digest: 'Digest має виглядати як sha256:<64 шістнадцяткові символи>.',
      ap_e_image: 'Вкажіть імʼя образу (наприклад, ghcr.io/owner/app).',
      ap_e_commit: 'Коміт має містити 7-40 шістнадцяткових символів.',
      ap_nowallet: 'У цьому браузері не знайдено гаманця Solana. Встановіть Phantom або Solflare й перезавантажте сторінку.',
      ap_refused: 'Підключення гаманця відхилено: {msg}',
      ap_waiting: 'Чекаю на підпис у гаманці…',
      ap_sending: 'Надсилаю…',
      ap_done_approve: 'Затверджено. Підписав {w}',
      ap_done_revoke: 'Відкликано. Підписав {w}',
      ap_hint_approve: 'Перевірка з обома підписантами: oath verify --signer {ci},{w} --quorum 2 --digest {d}',
      ap_hint_revoke: 'Тепер oath verify показує цей digest як REVOKED.',
      ap_view_tx: 'Переглянути транзакцію в Solana Explorer',
      ap_fail: 'Не підписано або не надіслано: {msg}',
    },
  };
  let lang = 'en';
  const t = (key, vars) => {
    let s = (I18N[lang] && I18N[lang][key]) ?? I18N.en[key] ?? key;
    if (vars) for (const k of Object.keys(vars)) s = s.split('{' + k + '}').join(String(vars[k]));
    return s;
  };

  // web3.js wants its own Buffer type for instruction data but does not export it; an instance of it is available from any PublicKey.
  const bufferFrom = (bytes) => wallet.toBuffer().constructor.from(bytes);
  const clean = (s) => String(s || '').replace(/[|\r\n]+/g, ' ').trim();

  /* ---- signed messages (offline approvals): the same text and the same rules as lib/approval.mjs ---- */
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function b58encode(bytes) {
    let n = 0n;
    for (const b of bytes) n = n * 256n + BigInt(b);
    let out = '';
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of bytes) { if (b === 0) out = '1' + out; else break; }
    return out;
  }
  // same normalisation as repoName() in lib/oath.mjs: lowercase, no tag, no digest, docker.io for bare names
  function normImage(ref) {
    let r = String(ref).trim().replace(/@sha256:[0-9a-f]{64}$/i, '');
    const slash = r.lastIndexOf('/'), colon = r.lastIndexOf(':');
    if (colon > slash) r = r.slice(0, colon);
    const parts = r.split('/');
    if (parts.length === 1) r = 'docker.io/library/' + r;
    else if (!/[.:]/.test(parts[0]) && parts[0] !== 'localhost') r = 'docker.io/' + r;
    return r.toLowerCase();
  }
  const isMsgMode = () => $('a-mode').value.startsWith('msg-');
  function buildMessage(now) {
    const mode = $('a-mode').value;
    const digest = $('a-digest').value.trim().toLowerCase();
    if (!DIGEST_RE.test(digest)) return { error: t('ap_e_digest') };
    const iso = now.toISOString();
    if (mode === 'msg-revoke') return { text: ['oath revocation v1', 'digest: ' + digest, 'reason: ' + clean($('a-reason').value).slice(0, 100), 'issued: ' + iso].join('\n') };
    const image = $('a-image').value.trim();
    const commit = $('a-commit').value.trim().toLowerCase();
    const days = Number($('a-days').value);
    if (!image) return { error: t('ap_e_image') };
    if (!/^[0-9a-f]{7,40}$/.test(commit)) return { error: t('ap_e_commit') };
    if (!(days >= 1 && days <= 366)) return { error: t('ap_e_days') };
    const expires = new Date(now.getTime() + days * 86400000).toISOString();
    return { text: ['oath approval v1', 'image: ' + normImage(image), 'digest: ' + digest, 'commit: ' + commit.slice(0, 12), 'approved: ' + iso, 'expires: ' + expires].join('\n') };
  }

  // Returns { text, error }. `text` is the memo to sign (time is filled in when signing).
  function build(now) {
    const mode = $('a-mode').value;
    if (isMsgMode()) return buildMessage(now || new Date());
    const digest = $('a-digest').value.trim().toLowerCase();
    if (!DIGEST_RE.test(digest)) return { error: t('ap_e_digest') };
    const iso = (now || new Date()).toISOString();
    if (mode === 'revoke') return { text: `pod1r|${digest}|${clean($('a-reason').value).slice(0, 100)}|${iso}` };
    const image = clean($('a-image').value);
    const commit = $('a-commit').value.trim().toLowerCase();
    if (!image) return { error: t('ap_e_image') };
    if (!/^[0-9a-f]{7,40}$/.test(commit)) return { error: t('ap_e_commit') };
    return { text: `pod1|${image}|${commit.slice(0, 12)}|${digest}|${iso}` };
  }

  function refresh() {
    const mode = $('a-mode').value;
    const isRevoke = mode === 'revoke' || mode === 'msg-revoke';
    $('f-image').hidden = isRevoke; $('f-commit').hidden = isRevoke; $('f-reason').hidden = !isRevoke;
    $('f-days').hidden = mode !== 'msg-approve';
    $('a-net').closest('.field').hidden = isMsgMode();
    $('prev-l').textContent = isMsgMode() ? t('ap_msg_l') : t('ap_preview_l');
    const b = build(new Date(0));
    const pre = $('a-preview');
    if (b.error) { pre.textContent = t('ap_fill'); $('a-err').hidden = true; }
    else if (isMsgMode()) { pre.textContent = b.text.replace(/(approved|issued): 1970-01-01T00:00:00\.000Z/, '$1: ' + t('ap_when')).replace(/expires: [0-9T:.Z-]+/, 'expires: ' + (mode === 'msg-approve' ? '+' + $('a-days').value + ' d' : '')); $('a-err').hidden = true; }
    else { pre.textContent = b.text.replace(/\|1970-01-01T00:00:00\.000Z$/, '|' + t('ap_time')); $('a-err').hidden = true; }
    $('a-sign').disabled = !wallet || !!b.error;
  }

  /* Every injected Solana wallet, not just the first: with Phantom and Solflare both installed, Phantom used to win silently. */
  function findProviders() {
    const cands = [
      ['Phantom', window.phantom && window.phantom.solana],
      ['Solflare', window.solflare],
      ['Backpack', window.backpack],
      [t('ap_wallet_other'), window.solana],
    ];
    const seen = new Set(), out = [];
    for (const [name, p] of cands) if (p && !seen.has(p)) { seen.add(p); out.push({ name, p }); }
    return out;
  }

  function fillPicker() {
    const list = findProviders(), pick = $('a-pick'), prev = pick.value;
    pick.replaceChildren();
    list.forEach((w, i) => { const o = document.createElement('option'); o.value = String(i); o.textContent = w.name; pick.appendChild(o); });
    if (prev && Number(prev) < list.length) pick.value = prev;
    pick.hidden = list.length < 2; // a choice only when there is one
    return list;
  }

  async function connect() {
    const list = fillPicker();
    if (!list.length) { show('bad', [['ap_nowallet']]); return; }
    provider = list[Number($('a-pick').value) || 0].p;
    try {
      const res = await provider.connect();
      const pk = (res && res.publicKey) || provider.publicKey;
      wallet = new solanaWeb3.PublicKey(pk.toString());
      $('a-wallet').removeAttribute('data-i18n');
      $('a-wallet').textContent = wallet.toBase58();
      refresh();
    } catch (e) {
      show('bad', [['ap_refused', { msg: e && e.message ? e.message : e }]]);
    }
  }

  /* The result area is re-rendered on language change, so what is shown is kept as data:
     a line is a plain string (shown as is) or [i18nKey, vars]. */
  let last = null;
  function show(kind, lines, link) {
    last = { kind, lines, link };
    const out = $('out');
    out.replaceChildren();
    for (const l of lines) {
      const d = document.createElement('div');
      d.textContent = Array.isArray(l) ? t(l[0], l[1]) : l;
      if (kind === 'bad') d.className = 'badc';
      if (kind === 'ok') d.className = 'good';
      out.appendChild(d);
    }
    if (link) {
      const d = document.createElement('div');
      const a = document.createElement('a');
      a.href = link; a.target = '_blank'; a.rel = 'noopener'; a.textContent = t('ap_view_tx');
      d.appendChild(a); out.appendChild(d);
    }
  }

  /* wallet.signMessage: an ed25519 signature over the text, no transaction, no network. Phantom and Solflare both offer it; the
     result is { signature } in some wallets and the bytes themselves in others. */
  async function signText(b) {
    $('a-sign').disabled = true;
    show('', [['ap_waiting']]);
    try {
      const res = await provider.signMessage(new TextEncoder().encode(b.text), 'utf8');
      const sig = res && res.signature ? res.signature : res;
      const stmt = { v: 1, message: b.text, signer: wallet.toBase58(), signature: b58encode(new Uint8Array(sig)) };
      const json = JSON.stringify(stmt, null, 2) + '\n';
      show('ok', [['ap_signed', { w: wallet.toBase58() }]]);
      $('a-json').value = json;
      const revoke = $('a-mode').value === 'msg-revoke';
      const digest = $('a-digest').value.trim().toLowerCase();
      const file = (revoke ? 'oath-revocation-' : 'oath-approval-') + digest.slice(7, 19) + '.json';
      $('a-result').hidden = false;
      $('a-dl').onclick = () => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
        a.download = file; document.body.appendChild(a); a.click(); a.remove();
      };
      $('a-cp').onclick = async () => { try { await navigator.clipboard.writeText(json); } catch { $('a-json').select(); } };
      $('a-how').textContent = [
        '# check it (offline)',
        'oath verify --signer ' + wallet.toBase58() + ' --image <name>@' + digest + ' --approvals ' + file,
        '',
        '# Kubernetes: keep all approval files in one folder, then',
        'kubectl -n oath-system create configmap oath-approvals --from-file=<folder> --dry-run=client -o yaml | kubectl apply -f -',
      ].join('\n');
    } catch (e) {
      show('bad', [['ap_fail', { msg: e && e.message ? e.message : e }]]);
    } finally {
      refresh();
    }
  }

  async function sign(ev) {
    ev.preventDefault();
    const b = build(new Date());
    if (b.error) { $('a-err').textContent = b.error; $('a-err').hidden = false; return; }
    if (!wallet || !provider) return;
    if (isMsgMode()) return signText(b);
    const net = NETS[$('a-net').value] || NETS.devnet;
    const { Connection, Transaction, TransactionInstruction, PublicKey } = solanaWeb3;
    $('a-sign').disabled = true;
    show('', [['ap_waiting']]);
    try {
      const conn = new Connection(net.rpc, 'confirmed');
      const ix = new TransactionInstruction({
        programId: new PublicKey(MEMO_PROGRAM),
        keys: [{ pubkey: wallet, isSigner: true, isWritable: false }],
        data: bufferFrom(new TextEncoder().encode(b.text)),
      });
      const tx = new Transaction().add(ix);
      tx.feePayer = wallet;
      const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash('confirmed');
      tx.recentBlockhash = blockhash;
      const signed = await provider.signTransaction(tx);
      show('', [['ap_sending']]);
      const signature = await conn.sendRawTransaction(signed.serialize());
      await conn.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, 'confirmed');
      const revoke = $('a-mode').value === 'revoke';
      const ci = new URLSearchParams(location.search).get('ci') || '<ci key>';
      show('ok', [
        [revoke ? 'ap_done_revoke' : 'ap_done_approve', { w: wallet.toBase58() }],
        b.text,
        '',
        revoke ? ['ap_hint_revoke'] : ['ap_hint_approve', { ci, w: wallet.toBase58(), d: $('a-digest').value.trim() }],
      ], `https://explorer.solana.com/tx/${encodeURIComponent(signature)}?cluster=${net.cluster}`);
    } catch (e) {
      show('bad', [['ap_fail', { msg: e && e.message ? e.message : e }]]);
    } finally {
      refresh();
    }
  }

  function applyLang(next) {
    lang = next;
    document.documentElement.lang = lang;
    for (const n of document.querySelectorAll('[data-i18n]')) n.textContent = t(n.dataset.i18n);
    for (const n of document.querySelectorAll('[data-i18n-attr]')) {
      for (const pair of n.dataset.i18nAttr.split(',')) {
        const [attr, key] = pair.split(':');
        n.setAttribute(attr.trim(), t(key.trim()));
      }
    }
    for (const b of document.querySelectorAll('.lang [data-lang]')) b.setAttribute('aria-pressed', b.dataset.lang === lang ? 'true' : 'false');
    for (const a of document.querySelectorAll('a[data-keep-lang]')) a.setAttribute('href', a.dataset.keepLang + '?lang=' + lang);
    if (last) show(last.kind, last.lines, last.link);
    refresh();
    try {
      const q = new URLSearchParams(location.search);
      q.set('lang', lang);
      history.replaceState(null, '', '?' + q.toString() + location.hash);
    } catch { /* file:// and sandboxed frames may refuse; not important */ }
  }

  function init() {
    const q = new URLSearchParams(location.search);
    const set = (id, v) => { if (v) $(id).value = v; };
    set('a-image', q.get('image')); set('a-commit', q.get('commit')); set('a-digest', q.get('digest')); set('a-reason', q.get('reason'));
    if (q.get('net') && NETS[q.get('net')]) $('a-net').value = q.get('net');
    if (['revoke', 'msg-approve', 'msg-revoke'].includes(q.get('mode'))) $('a-mode').value = q.get('mode');
    for (const id of ['a-mode', 'a-image', 'a-commit', 'a-digest', 'a-reason', 'a-net', 'a-days']) $(id).addEventListener('input', refresh);
    $('a-connect').addEventListener('click', connect);
    window.addEventListener('load', fillPicker); // wallets inject their provider late
    $('a-pick').addEventListener('change', () => { wallet = null; provider = null; const w = $('a-wallet'); w.setAttribute('data-i18n', 'ap_not_connected'); w.textContent = t('ap_not_connected'); refresh(); });
    $('aform').addEventListener('submit', sign);
    for (const b of document.querySelectorAll('.lang [data-lang]')) b.addEventListener('click', () => applyLang(b.dataset.lang));
    const ql = (q.get('lang') || '').toLowerCase();
    applyLang(ql === 'uk' || ql === 'en' ? ql : ((navigator.language || 'en').toLowerCase().startsWith('uk') ? 'uk' : 'en'));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();

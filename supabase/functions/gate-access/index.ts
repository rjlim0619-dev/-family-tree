import { createClient } from 'npm:@supabase/supabase-js@2';

// =====================  GATE CONFIG  (the ONE place to change gate timings; the app follows these)  =====================
const CONFIG = {
  // The ONLY place a code is ever sent. It lives on the server: the secret DEVELOPER_EMAIL, or (if that is not set) the private
  // table gate_settings (no policies, service role only). Never in the repo, never in the page.
  DEVELOPER_EMAIL: (Deno.env.get('DEVELOPER_EMAIL') || '').trim().toLowerCase(),
  SHOW_FULL_DEVELOPER_EMAIL: Deno.env.get('SHOW_FULL_DEVELOPER_EMAIL') === 'true', // false = the page shows "rj•••••@gmail.com"
  ASK_NAME: Deno.env.get('ASK_NAME') !== 'false',   // optional "Your name" field (secret ASK_NAME=false turns it off)
  TURNSTILE_SECRET: Deno.env.get('TURNSTILE_SECRET') || '', // optional Cloudflare Turnstile; empty = no human check
  TIMEZONE: 'Asia/Manila',
  CODE_TTL_S: 15 * 60,      // how long an emailed code can be entered
  COOLDOWN_S: 60,          // wait between code requests for one email
  MAX_ATTEMPTS: 5,         // wrong guesses per code
  GRACE_S: 120,            // tab hidden / no heartbeat for this long -> gate relocks (default 2 min)
  IDLE_S: 300,             // no clicks/typing for this long -> gate relocks (default 5 min)
  MAX_WINDOW_S: 15 * 60,   // total access time after the code was verified, even while active (default 15 min)
  LEAVE_GRACE_S: 15,       // page refresh tolerance after the tab says it is leaving
  HEARTBEAT_S: 30,         // how often the open tab pings the server
  REQ_IP_PER_HOUR: 3, REQ_DEVICE_PER_HOUR: 3, REQ_GLOBAL_PER_DAY: 30, VERIFY_IP_PER_HOUR: 30,
};
// =======================================================================================================================
const HOUR = 3_600_000, DAY = 24 * HOUR;
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { ...CORS, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, '0')).join('');
const sha256 = async (s: string) => hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)));
// Codes are only 6 digits, so they are HMAC'd with a server-only secret (a leaked table can't be brute-forced offline).
const hmacKey = (() => { let k: Promise<CryptoKey> | null = null; return () => k ??= crypto.subtle.importKey('raw', new TextEncoder().encode(Deno.env.get('GATE_PEPPER') || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); })();
const mac = async (s: string) => hex(await crypto.subtle.sign('HMAC', await hmacKey(), new TextEncoder().encode(s)));
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const maskEmail = (e: string) => { const [l, d] = e.split('@'); return (l || '').slice(0, 2) + '•••••@' + (d || ''); };
// Visitor-supplied name: strip HTML/links/addresses/odd characters, cap the length, refuse abusive words.
const BAD = /\b(fuck\w*|shit\w*|bitch\w*|asshole|bastard|cunt|dick\w*|nigg\w*|puta\w*|tangina\w*|gago|ulol|bobo|tanga)\b/i;
const cleanName = (raw: unknown): string | null => {
  const n = String(raw ?? '').normalize('NFKC').replace(/<[^>]*>/g, ' ').replace(/(https?:\/\/|www\.)\S*/gi, ' ').replace(/\S+@\S+/g, ' ')
    .replace(/[^\p{L}\p{N} .'\-]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 40);
  return BAD.test(n) ? null : n;
};
const device = (ua: string) => {
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Unknown browser';
  const o = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return `${b} on ${o}${/Mobi/.test(ua) ? ' (mobile)' : ''}`;
};
const iso = (ms: number) => new Date(ms).toISOString();
const policy = () => ({ expires_in: CONFIG.MAX_WINDOW_S, grace: CONFIG.GRACE_S, idle: CONFIG.IDLE_S, heartbeat: CONFIG.HEARTBEAT_S, leave_grace: CONFIG.LEAVE_GRACE_S });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: CORS });
  if (req.method !== 'POST') return json({ status: 'error' }, 405);
  // navigator.sendBeacon sends text/plain, so read the body as text and parse it ourselves.
  let body: any; try { body = JSON.parse(await req.text()); } catch { return json({ status: 'error' }, 400); }
  const db = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  const ip = (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim();
  const now = Date.now(); // all expiry decisions use SERVER time, never the visitor's clock
  if (!CONFIG.DEVELOPER_EMAIL && (body.action === 'info' || body.action === 'owner' || body.action === 'request')) {
    const { data: st } = await db.from('gate_settings').select('value').eq('key', 'DEVELOPER_EMAIL').maybeSingle();
    CONFIG.DEVELOPER_EMAIL = String(st?.value || '').trim().toLowerCase();
  }

  // ---- gate token actions (no email needed) ----
  if (body.action === 'heartbeat' || body.action === 'validate') {
    const tok = String(body.token || ''); if (tok.length < 20) return json({ status: 'locked', reason: 'none', server_now: now }, 410);
    const h = await sha256(tok);
    const { data: row } = await db.from('gate_tokens').select('*').eq('token_hash', h).maybeSingle();
    if (!row) return json({ status: 'locked', reason: 'none', server_now: now }, 410);
    const exp = new Date(row.expires_at).getTime(), vu = new Date(row.valid_until).getTime();
    if (now >= exp) { await db.from('gate_tokens').delete().eq('token_hash', h); return json({ status: 'locked', reason: 'expired', server_now: now }, 410); }
    if (now >= vu) { await db.from('gate_tokens').delete().eq('token_hash', h); return json({ status: 'locked', reason: 'away', server_now: now }, 410); }
    // idle is reported by the page; the hard maximum window above can not be extended by the page.
    const idleMs = Math.max(0, Math.min(Number(body.idle_ms) || 0, CONFIG.IDLE_S * 1000 * 2));
    const idleLeft = CONFIG.IDLE_S * 1000 - idleMs;
    if (idleLeft <= 0) { await db.from('gate_tokens').delete().eq('token_hash', h); return json({ status: 'locked', reason: 'idle', server_now: now }, 410); }
    const next = Math.min(exp, now + CONFIG.GRACE_S * 1000, now + idleLeft);
    await db.from('gate_tokens').update({ valid_until: iso(next) }).eq('token_hash', h);
    return json({ status: 'ok', remaining_ms: exp - now, server_now: now, ...policy() });
  }
  if (body.action === 'leave') {            // tab closing/refreshing: only a short grace (so a refresh survives), then it is dead
    const tok = String(body.token || ''); if (tok.length < 20) return json({ status: 'ok' });
    const h = await sha256(tok);
    const { data: row } = await db.from('gate_tokens').select('valid_until').eq('token_hash', h).maybeSingle();
    if (row) await db.from('gate_tokens').update({ valid_until: iso(Math.min(new Date(row.valid_until).getTime(), now + CONFIG.LEAVE_GRACE_S * 1000)) }).eq('token_hash', h);
    return json({ status: 'ok' });
  }
  if (body.action === 'revoke') {           // "Lock now" / explicit relock: gone immediately
    const tok = String(body.token || ''); if (tok.length >= 20) await db.from('gate_tokens').delete().eq('token_hash', await sha256(tok));
    return json({ status: 'ok' });
  }

  // ---- access code actions ----
  // The page NEVER chooses a recipient. Any "email" field in the request body is ignored, on purpose.
  const count = async (kind: string, key: string, win = HOUR) => (await db.from('gate_rate').select('id', { count: 'exact', head: true }).eq('kind', kind).eq('key', key).gte('at', iso(Date.now() - win))).count || 0;
  const mark = (kind: string, key: string) => db.from('gate_rate').insert({ kind, key });
  // seconds until the oldest hit in the window falls out, i.e. when the visitor may try again
  const waitFor = async (kind: string, key: string, win: number) => { const { data } = await db.from('gate_rate').select('at').eq('kind', kind).eq('key', key).gte('at', iso(now - win)).order('at', { ascending: true }).limit(1); return data?.length ? Math.max(1, Math.ceil((new Date(data[0].at).getTime() + win - now) / 1000)) : 60; };
  // housekeeping on every call: expired rate rows, codes, tokens and old log lines are deleted
  Promise.all([
    db.from('gate_rate').delete().lt('at', iso(now - DAY - HOUR)),
    db.from('gate_codes').delete().lt('expires_at', iso(now - HOUR)),
    db.from('gate_tokens').delete().lt('valid_until', iso(now - HOUR)),
    db.from('gate_log').delete().lt('at', iso(now - 30 * DAY)),
  ]).then(() => {}, () => {});

  if (body.action === 'diag') {              // the page reports its own screen state when something looks wrong (no personal data)
    const ipH = await mac('ip:' + ip);
    if ((await count('diag', ipH)) >= 30) return json({ status: 'limited' }, 429);
    await mark('diag', ipH);
    await db.from('gate_log').insert({ ip_hash: ipH, name: String(body.s || '').slice(0, 700), device: device(req.headers.get('user-agent') || ''), outcome: 'diag:' + String(body.r || '').slice(0, 16) });
    return json({ status: 'ok' });
  }
  if (body.action === 'info') {              // what the locked "Request goes to" field shows (the page never holds the address)
    const to = !CONFIG.DEVELOPER_EMAIL ? '' : CONFIG.SHOW_FULL_DEVELOPER_EMAIL ? CONFIG.DEVELOPER_EMAIL : maskEmail(CONFIG.DEVELOPER_EMAIL);
    return json({ status: 'ok', to, ask_name: CONFIG.ASK_NAME, human_check: !!CONFIG.TURNSTILE_SECRET });
  }
  if (body.action === 'owner') {             // is the signed-in user the developer? (decided here, so the page needs no address)
    const jwt = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
    const { data } = jwt ? await db.auth.getUser(jwt) : { data: null as any };
    const me = String(data?.user?.email || '').toLowerCase();
    const owner = !!CONFIG.DEVELOPER_EMAIL && me === CONFIG.DEVELOPER_EMAIL;
    return json({ status: 'ok', owner, owner_email: owner ? me : null });
  }

  if (body.action === 'request') {
    if (!CONFIG.DEVELOPER_EMAIL) return json({ status: 'not_configured' }, 503);
    let key = Deno.env.get('RESEND_API_KEY') || ''; if (!key) { const { data: rk } = await db.from('gate_settings').select('value').eq('key', 'RESEND_API_KEY').maybeSingle(); key = String(rk?.value || ''); } if (!key) return json({ status: 'not_configured' }, 503);
    const ipH = await mac('ip:' + ip);
    const devId = String(body.device || '').slice(0, 64), devH = /^[0-9a-f-]{16,64}$/i.test(devId) ? await mac('dev:' + devId) : '';
    const ua = req.headers.get('user-agent') || ''; const dev = device(ua);
    const log = (outcome: string, name = '') => db.from('gate_log').insert({ ip_hash: ipH, device_hash: devH || null, name: name || null, device: dev, outcome });
    let name = '';
    if (CONFIG.ASK_NAME) { const n = cleanName(body.name); if (n === null) { await log('bad_name'); return json({ status: 'bad_name' }, 400); } name = n; }
    if (CONFIG.TURNSTILE_SECRET) {            // optional human check
      let ok = false; const t = String(body.turnstile || '');
      if (t) { try { const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: new URLSearchParams({ secret: CONFIG.TURNSTILE_SECRET, response: t, remoteip: ip }) }); ok = !!(await r.json()).success; } catch { ok = false; } }
      if (!ok) { await log('human_check'); return json({ status: 'human_check' }, 403); }
    }
    // cooldown first (a visitor can't hammer the button), then the hourly and daily ceilings
    for (const [k, v] of [['req_dev', devH], ['req_ip', ipH]] as const) {
      if (!v) continue;
      const { data: last } = await db.from('gate_rate').select('at').eq('kind', k).eq('key', v).gte('at', iso(now - CONFIG.COOLDOWN_S * 1000)).order('at', { ascending: false }).limit(1);
      if (last?.length) { const w = Math.max(1, Math.ceil((new Date(last[0].at).getTime() + CONFIG.COOLDOWN_S * 1000 - now) / 1000)); await log('wait'); return json({ status: 'wait', retry_after: w }, 429); }
    }
    let lim = 0;
    if ((await count('req_ip', ipH)) >= CONFIG.REQ_IP_PER_HOUR) lim = await waitFor('req_ip', ipH, HOUR);
    else if (devH && (await count('req_dev', devH)) >= CONFIG.REQ_DEVICE_PER_HOUR) lim = await waitFor('req_dev', devH, HOUR);
    else if ((await count('req_all', 'all', DAY)) >= CONFIG.REQ_GLOBAL_PER_DAY) lim = await waitFor('req_all', 'all', DAY);
    if (lim) { await log('limited'); return json({ status: 'limited', retry_after: lim }, 429); }
    await Promise.all([mark('req_ip', ipH), devH ? mark('req_dev', devH) : null, mark('req_all', 'all')]);
    if (body.prev && /^rid:[0-9a-f]{32}$/.test(String(body.prev))) await db.from('gate_codes').delete().eq('email', String(body.prev)); // an older code from this visitor dies when they ask again
    const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    const rid = 'rid:' + hex(crypto.getRandomValues(new Uint8Array(16)).buffer);   // opaque id the page keeps in sessionStorage; the key for this code
    await db.from('gate_codes').insert({ email: rid, code_hash: await mac(code + ':' + rid), expires_at: iso(now + CONFIG.CODE_TTL_S * 1000), attempts: 0, created_at: iso(now) });
    const when = new Date(now).toLocaleString('en-PH', { timeZone: CONFIG.TIMEZONE, dateStyle: 'medium', timeStyle: 'short' });
    const who = name || 'Someone';
    const mins = CONFIG.CODE_TTL_S / 60;
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'Family Tree <onboarding@resend.dev>', to: [CONFIG.DEVELOPER_EMAIL], subject: 'Family Tree access request — ' + code,
        text: `${who} requested access.\nCode: ${code} · valid for ${mins} minutes.\n\nWhen: ${when} (${CONFIG.TIMEZONE})\nDevice: ${dev}\n\nIf you don't recognize this request, ignore this email.`,
        html: `<div style="font-family:system-ui,sans-serif;max-width:480px"><p style="font-size:16px"><b>${esc(who)}</b> requested access.</p><p style="font-size:32px;letter-spacing:6px;font-weight:700;margin:12px 0">${code}</p><p>Code: <b>${code}</b> · valid for ${mins} minutes. It works once.</p><p style="color:#555;font-size:13px">When: ${esc(when)} (${CONFIG.TIMEZONE})<br>Device: ${esc(dev)}</p><p style="color:#666;font-size:12px">If you don't recognize this request, ignore this email. Give the code only to someone you approve.</p></div>` }),
    });
    if (!r.ok) { await db.from('gate_codes').delete().eq('email', rid); await log('send_failed', name); return json({ status: 'send_failed' }, 502); }
    await log('sent', name);   // the code itself is never logged
    return json({ status: 'sent', rid, cooldown: CONFIG.COOLDOWN_S, expires_in: CONFIG.CODE_TTL_S });
  }

  if (body.action === 'verify') {
    const code = String(body.code || '').replace(/\D/g, '');
    const email = String(body.rid || '');     // "email" column = the opaque request id
    if (!/^rid:[0-9a-f]{32}$/.test(email)) return json({ status: 'expired' }, 410);
    if (code.length !== 6) return json({ status: 'bad_code' }, 400);
    const vIp = await mac('ip:' + ip);
    if ((await count('ver_ip', vIp)) >= CONFIG.VERIFY_IP_PER_HOUR) return json({ status: 'limited', retry_after: 3600 }, 429);
    await mark('ver_ip', vIp);
    const { data: row } = await db.from('gate_codes').select('*').eq('email', email).maybeSingle();
    if (!row || new Date(row.expires_at).getTime() < now) { if (row) await db.from('gate_codes').delete().eq('email', email); return json({ status: 'expired' }, 410); }
    if (row.attempts >= CONFIG.MAX_ATTEMPTS) { await db.from('gate_codes').delete().eq('email', email); return json({ status: 'locked' }, 429); }
    const { data: bumped } = await db.from('gate_codes').update({ attempts: row.attempts + 1 }).eq('email', email).eq('attempts', row.attempts).select('attempts');
    if (!bumped || !bumped.length) return json({ status: 'wait', retry_after: 2 }, 429);
    if ((await mac(code + ':' + email)) !== row.code_hash) {
      const left = CONFIG.MAX_ATTEMPTS - (row.attempts + 1);
      if (left <= 0) { await db.from('gate_codes').delete().eq('email', email); return json({ status: 'locked' }, 429); }
      return json({ status: 'wrong', left }, 401);
    }
    // One-time code: deleted the moment it is accepted. It is exchanged for a short-lived gate token (stored only as a hash).
    const { data: used } = await db.from('gate_codes').delete().eq('email', email).eq('code_hash', row.code_hash).select('email');
    if (!used || !used.length) return json({ status: 'expired' }, 410);
    const tok = hex(crypto.getRandomValues(new Uint8Array(32)).buffer);
    await db.from('gate_tokens').insert({ token_hash: await sha256(tok), email, expires_at: iso(now + CONFIG.MAX_WINDOW_S * 1000), valid_until: iso(now + Math.min(CONFIG.GRACE_S, CONFIG.IDLE_S) * 1000) });
    return json({ status: 'approved', token: tok, server_now: now, ...policy() });
  }
  return json({ status: 'error' }, 400);
});

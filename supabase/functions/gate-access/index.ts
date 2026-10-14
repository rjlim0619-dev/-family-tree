import { createClient } from 'npm:@supabase/supabase-js@2';

// =====================  GATE CONFIG  (the ONE place to change gate timings; the app follows these)  =====================
const CONFIG = {
  DEVELOPER_EMAIL: Deno.env.get('DEVELOPER_EMAIL') || 'rjlim060719@gmail.com', // the access code is emailed here, only here
  CODE_TTL_S: 15 * 60,      // how long an emailed code can be entered
  COOLDOWN_S: 60,          // wait between code requests for one email
  MAX_ATTEMPTS: 5,         // wrong guesses per code
  GRACE_S: 120,            // tab hidden / no heartbeat for this long -> gate relocks (default 2 min)
  IDLE_S: 300,             // no clicks/typing for this long -> gate relocks (default 5 min)
  MAX_WINDOW_S: 15 * 60,   // total access time after the code was verified, even while active (default 15 min)
  LEAVE_GRACE_S: 15,       // page refresh tolerance after the tab says it is leaving
  HEARTBEAT_S: 30,         // how often the open tab pings the server
  EMAIL_PER_HOUR: 3, IP_PER_HOUR: 6, VERIFY_IP_PER_HOUR: 30,
};
// =======================================================================================================================
const HOUR = 3_600_000;
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
  const email = String(body.email || '').trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 254) return json({ status: 'invalid_email' }, 400);
  const since = () => iso(Date.now() - HOUR);
  const count = async (kind: string, key: string) => (await db.from('gate_rate').select('id', { count: 'exact', head: true }).eq('kind', kind).eq('key', key).gte('at', since())).count || 0;
  const mark = (kind: string, key: string) => db.from('gate_rate').insert({ kind, key });
  // housekeeping on every call: expired rate rows, codes and tokens are deleted
  Promise.all([
    db.from('gate_rate').delete().lt('at', iso(now - 2 * HOUR)),
    db.from('gate_codes').delete().lt('expires_at', iso(now - HOUR)),
    db.from('gate_tokens').delete().lt('valid_until', iso(now - HOUR)),
  ]).then(() => {}, () => {});

  if (body.action === 'request') {
    const { data: acc } = await db.from('access_requests').select('status').eq('email', email).maybeSingle();
    const denied = acc?.status === 'denied';   // a denied email gets the same reply as everyone, so nothing is revealed
    const { data: prev } = await db.from('gate_codes').select('created_at').eq('email', email).maybeSingle();
    if (prev) { const w = CONFIG.COOLDOWN_S * 1000 - (now - new Date(prev.created_at).getTime()); if (w > 0) return json({ status: 'wait', retry_after: Math.ceil(w / 1000) }, 429); }
    if ((await count('req_email', email)) >= CONFIG.EMAIL_PER_HOUR || (await count('req_ip', ip)) >= CONFIG.IP_PER_HOUR) return json({ status: 'limited', retry_after: 3600 }, 429);
    await Promise.all([mark('req_email', email), mark('req_ip', ip)]);
    if (denied) return json({ status: 'sent', cooldown: CONFIG.COOLDOWN_S, expires_in: CONFIG.CODE_TTL_S });
    const key = Deno.env.get('RESEND_API_KEY');
    if (!key) return json({ status: 'not_configured' }, 503);
    const code = String(100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000));
    await db.from('gate_codes').upsert({ email, code_hash: await mac(code + ':' + email), expires_at: iso(now + CONFIG.CODE_TTL_S * 1000), attempts: 0, created_at: iso(now) });
    await db.from('access_requests').upsert({ email, status: 'pending' }, { onConflict: 'email', ignoreDuplicates: true });
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: 'Family Tree <onboarding@resend.dev>', to: [CONFIG.DEVELOPER_EMAIL], subject: 'Family Tree access code: ' + code,
        html: `<div style="font-family:system-ui,sans-serif"><p><b>${esc(email)}</b> is asking for access to your Family Tree.</p><p style="font-size:32px;letter-spacing:6px;font-weight:700">${code}</p><p>Give them this code only if you approve. It expires in ${CONFIG.CODE_TTL_S / 60} minutes and works once. After they enter it, access closes by itself when they leave, go idle, or after ${CONFIG.MAX_WINDOW_S / 60} minutes.</p><p style="color:#666;font-size:12px">Request from IP ${esc(ip)} at ${iso(now)}. If you do not know them, ignore this email.</p></div>` }),
    });
    if (!r.ok) { await db.from('gate_codes').delete().eq('email', email); return json({ status: 'send_failed' }, 502); }
    return json({ status: 'sent', cooldown: CONFIG.COOLDOWN_S, expires_in: CONFIG.CODE_TTL_S });
  }

  if (body.action === 'verify') {
    const code = String(body.code || '').replace(/\D/g, '');
    if (code.length !== 6) return json({ status: 'bad_code' }, 400);
    if ((await count('ver_ip', ip)) >= CONFIG.VERIFY_IP_PER_HOUR) return json({ status: 'limited', retry_after: 3600 }, 429);
    await mark('ver_ip', ip);
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
    await db.from('gate_tokens').delete().eq('email', email); // one live gate per email
    const tok = hex(crypto.getRandomValues(new Uint8Array(32)).buffer);
    await db.from('gate_tokens').insert({ token_hash: await sha256(tok), email, expires_at: iso(now + CONFIG.MAX_WINDOW_S * 1000), valid_until: iso(now + Math.min(CONFIG.GRACE_S, CONFIG.IDLE_S) * 1000) });
    return json({ status: 'approved', token: tok, server_now: now, ...policy() });
  }
  return json({ status: 'error' }, 400);
});

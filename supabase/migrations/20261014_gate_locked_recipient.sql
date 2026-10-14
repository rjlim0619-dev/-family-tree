-- Applied to project jfnuqozxhljkhlcnfnxh. gate_codes.email / gate_tokens.email now hold an opaque request id ("rid:<hex>").
create table if not exists public.gate_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  ip_hash text not null, device_hash text, name text, device text, outcome text not null
);
alter table public.gate_log enable row level security;  -- no policies: only the service role (edge function) can use it
create index if not exists gate_log_at_idx on public.gate_log(at);

create or replace function public.hook_before_user_created(event jsonb)
returns jsonb language plpgsql security definer set search_path to 'public' as $function$
declare
  t text := coalesce(event->'user'->'user_metadata'->>'gate_token','');
  h text := encode(sha256(convert_to(t,'UTF8')),'hex');
  n int;
begin
  delete from public.gate_tokens where token_hash = h and now() < valid_until and now() < expires_at;
  get diagnostics n = row_count;
  if n = 1 then return '{}'::jsonb; end if;
  return jsonb_build_object('error', jsonb_build_object('message','The access gate is closed. Request a new access code.','http_code',403));
end $function$;

-- Private server-side settings (no policies: only the edge function's service role can read it).
-- The developer address is inserted by hand, never committed:  insert into public.gate_settings values ('DEVELOPER_EMAIL','<address>');
create table if not exists public.gate_settings (key text primary key, value text not null);
alter table public.gate_settings enable row level security;

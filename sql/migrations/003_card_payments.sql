-- 003: debit-card payments via Stripe Checkout (redirect). Idempotent / additive: safe to re-run in the SQL editor.
-- Also merged into sql/schema.sql. Writers of the payment columns: the stripe-webhook Edge Function (service role) only.

alter table public.orders add column if not exists payment_status text not null default 'unpaid';
alter table public.orders add column if not exists stripe_session_id text;
alter table public.orders add column if not exists stripe_payment_intent text;
alter table public.orders add column if not exists paid_at timestamptz;
do $$ begin
  alter table public.orders add constraint orders_payment_status_chk
    check (payment_status in ('unpaid','paid','failed','expired','refunded'));
exception when duplicate_object then null; end $$;
create index if not exists orders_stripe_session_idx on public.orders(stripe_session_id) where stripe_session_id is not null;

-- webhook idempotency log: RLS on, no policies, no grants => unreachable from the browser (service role bypasses RLS)
create table if not exists public.processed_stripe_events (
  event_id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);
alter table public.processed_stripe_events enable row level security;
revoke all on public.processed_stripe_events from anon, authenticated;

-- order_json now exposes payment_status / paid_at (used by track_order); place_order accepts 'debit_card'
create or replace function public.order_json(p_order_id uuid) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object(
    'id', o.id, 'order_number', o.order_number, 'status', o.status,
    'items', coalesce((select jsonb_agg(jsonb_build_object(
        'product_id', i.product_id, 'name', i.name, 'image', i.image, 'unit_price', i.unit_price,
        'qty', i.qty, 'line_total', round(i.unit_price * i.qty, 2)) order by i.name)
      from public.order_items i where i.order_id = o.id), '[]'::jsonb),
    'subtotal', o.subtotal, 'discount', o.discount, 'shipping', o.shipping, 'total', o.total,
    'coupon_code', o.coupon_code, 'created_at', o.created_at, 'customer', o.customer,
    'payment_method', o.payment_method, 'payment_status', o.payment_status, 'paid_at', o.paid_at)
  from public.orders o where o.id = p_order_id;
$$;
revoke all on function public.order_json(uuid) from public, anon, authenticated;

create or replace function public.place_order(payload jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  cust jsonb := payload->'customer';
  v_email text := lower(trim(coalesce(cust->>'email', '')));
  v_pm text := payload->>'payment_method';
  v_code text := upper(trim(coalesce(payload->>'coupon_code', '')));
  v_oid uuid := gen_random_uuid();
  v_num text;
  r record; prod public.products; cp public.coupons;
  v_sub numeric(10,2) := 0; v_disc numeric(10,2) := 0;
begin
  if jsonb_typeof(cust) is distinct from 'object'
     or char_length(trim(coalesce(cust->>'name', ''))) not between 1 and 120
     or v_email !~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' or char_length(v_email) > 254
     or char_length(trim(coalesce(cust->>'address', ''))) not between 1 and 300
     or char_length(trim(coalesce(cust->>'city', ''))) not between 1 and 100
     or char_length(trim(coalesce(cust->>'country', ''))) not between 1 and 100
     or v_pm is null or v_pm not in ('debit_card', 'moncash', 'zelle', 'cash_on_delivery')
     or jsonb_typeof(payload->'items') is distinct from 'array'
     or jsonb_array_length(payload->'items') not between 1 and 50 then
    raise exception 'validation';
  end if;

  begin
    if exists (select 1 from jsonb_array_elements(payload->'items') e
      where (e->>'qty')::int not between 1 and 99 or (e->>'product_id')::uuid is null) then
      raise exception 'validation';
    end if;
  exception when others then raise exception 'validation';
  end;

  v_num := 'JPS-' || to_char(now(), 'YYMMDD') || '-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 4));
  while exists (select 1 from public.orders where order_number = v_num) loop
    v_num := 'JPS-' || to_char(now(), 'YYMMDD') || '-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 4));
  end loop;

  insert into public.orders (id, order_number, user_id, customer, customer_email, payment_method, subtotal, total)
  values (v_oid, v_num, auth.uid(),
    jsonb_build_object('name', trim(cust->>'name'), 'email', v_email, 'phone', left(trim(coalesce(cust->>'phone', '')), 40),
      'address', trim(cust->>'address'), 'city', trim(cust->>'city'), 'country', trim(cust->>'country'),
      'notes', left(trim(coalesce(cust->>'notes', '')), 1000)),
    v_email, v_pm, 0, 0);

  -- ordered by id to avoid deadlocks; duplicate product lines are merged
  for r in
    select (e->>'product_id')::uuid as pid, sum((e->>'qty')::int)::int as q
    from jsonb_array_elements(payload->'items') e group by 1 order by 1
  loop
    select * into prod from public.products where id = r.pid and is_active for update;
    if not found then raise exception 'not_found'; end if;
    if prod.stock < r.q then raise exception 'out_of_stock' using hint = prod.name; end if;
    update public.products set stock = stock - r.q where id = prod.id;
    insert into public.order_items (order_id, product_id, name, image, unit_price, qty)
      values (v_oid, prod.id, prod.name, prod.image, prod.price, r.q);
    v_sub := v_sub + round(prod.price * r.q, 2);
  end loop;

  if v_code <> '' then
    select * into cp from public.coupons where code = v_code;
    if not found or not cp.active or (cp.expires_at is not null and cp.expires_at < now()) or not (v_sub > cp.min_subtotal) then
      raise exception 'invalid_coupon';
    end if;
    v_disc := least(v_sub, round(v_sub * cp.percent / 100, 2));
  else
    v_code := null;
  end if;

  update public.orders set subtotal = v_sub, discount = v_disc, shipping = 0, total = v_sub - v_disc, coupon_code = v_code
  where id = v_oid;
  return public.order_json(v_oid);
end $$;
grant execute on function public.place_order(jsonb) to anon, authenticated;

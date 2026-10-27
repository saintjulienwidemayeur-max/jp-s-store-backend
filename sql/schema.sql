-- JP's Logistics & More: Supabase / Postgres schema. Run in the Supabase SQL editor. Idempotent.
-- No keys here. After creating the first admin account, promote it (see bottom).

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- tables
create table if not exists public.categories (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  name text not null,
  image text,
  sort_order int not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique,
  name text not null,
  description text not null default '',
  price numeric(10,2) not null check (price >= 0),
  compare_at_price numeric(10,2) check (compare_at_price is null or compare_at_price >= 0),
  category_id uuid references public.categories(id) on delete set null,
  image text,
  images text[] not null default '{}',
  rating numeric(2,1) not null default 5 check (rating between 0 and 5),
  review_count int not null default 0,
  stock int not null default 0 check (stock >= 0),
  is_active boolean not null default true,
  is_popular boolean not null default false,
  tags text[] not null default '{}',
  media jsonb not null default '[]'::jsonb, -- [{id,type,url,poster,alt,sort,is_cover,source,status,...}] (see migration 002)
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists products_category_idx on public.products(category_id);

create table if not exists public.product_images (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  url text not null,
  alt text,
  position int not null default 0
);

create table if not exists public.coupons (
  code text primary key check (code = upper(code)),
  percent numeric(5,2) not null check (percent > 0 and percent <= 100),
  min_subtotal numeric(10,2) not null default 0 check (min_subtotal >= 0),
  active boolean not null default true,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text not null default '',
  is_admin boolean not null default false,
  preferences jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.orders (
  id uuid primary key default gen_random_uuid(),
  order_number text not null unique,
  user_id uuid references auth.users(id) on delete set null,
  status text not null default 'pending' check (status in ('pending','paid','processing','shipped','delivered','cancelled')),
  customer jsonb not null,
  customer_email text not null,
  payment_method text not null,
  subtotal numeric(10,2) not null,
  discount numeric(10,2) not null default 0,
  shipping numeric(10,2) not null default 0,
  total numeric(10,2) not null,
  coupon_code text,
  payment_status text not null default 'unpaid' check (payment_status in ('unpaid','paid','failed','expired','refunded')), -- migration 003
  stripe_session_id text,
  stripe_payment_intent text,
  paid_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists orders_user_idx on public.orders(user_id);
create index if not exists orders_email_idx on public.orders(lower(customer_email));

create table if not exists public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  name text not null,
  image text,
  unit_price numeric(10,2) not null,
  qty int not null check (qty > 0)
);
create index if not exists order_items_order_idx on public.order_items(order_id);

create table if not exists public.wishlists (
  user_id uuid not null references auth.users(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, product_id)
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  user_name text not null default '',
  rating int not null check (rating between 1 and 5),
  comment text not null default '' check (char_length(comment) <= 2000),
  created_at timestamptz not null default now(),
  unique (product_id, user_id)
);

create table if not exists public.newsletter_subscribers (
  id uuid primary key default gen_random_uuid(),
  email text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' and char_length(email) <= 254),
  created_at timestamptz not null default now()
);
create unique index if not exists newsletter_email_uq on public.newsletter_subscribers(lower(email));

create table if not exists public.contact_messages (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  email text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' and char_length(email) <= 254),
  message text not null check (char_length(message) between 5 and 5000),
  handled boolean not null default false,
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------- helpers
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select p.is_admin from public.profiles p where p.id = auth.uid()), false);
$$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

-- profile on signup
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'name', ''))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- users cannot make themselves admin (SQL editor / service role, where auth.uid() is null, may)
create or replace function public.protect_profile_admin() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.is_admin is distinct from old.is_admin and auth.uid() is not null and not public.is_admin() then
    raise exception 'forbidden';
  end if;
  return new;
end $$;
drop trigger if exists profiles_protect_admin on public.profiles;
create trigger profiles_protect_admin before update on public.profiles
  for each row execute function public.protect_profile_admin();

create or replace function public.touch_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
drop trigger if exists products_touch on public.products;
create trigger products_touch before update on public.products for each row execute function public.touch_updated_at();
drop trigger if exists orders_touch on public.orders;
create trigger orders_touch before update on public.orders for each row execute function public.touch_updated_at();

-- reviews: set author name from profile, keep product rating in sync
create or replace function public.reviews_before_write() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.user_id := coalesce(new.user_id, auth.uid());
  select coalesce(nullif(p.name, ''), 'Customer') into new.user_name from public.profiles p where p.id = new.user_id;
  return new;
end $$;
drop trigger if exists reviews_bw on public.reviews;
create trigger reviews_bw before insert or update on public.reviews for each row execute function public.reviews_before_write();

create or replace function public.reviews_sync_rating() returns trigger
language plpgsql security definer set search_path = public as $$
declare pid uuid := coalesce(new.product_id, old.product_id);
begin
  update public.products p set
    review_count = (select count(*) from public.reviews r where r.product_id = pid),
    rating = coalesce((select round(avg(r.rating)::numeric, 1) from public.reviews r where r.product_id = pid), 5)
  where p.id = pid;
  return null;
end $$;
drop trigger if exists reviews_sync on public.reviews;
create trigger reviews_sync after insert or update or delete on public.reviews for each row execute function public.reviews_sync_rating();

-- ---------------------------------------------------------------- RLS
alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.product_images enable row level security;
alter table public.coupons enable row level security;
alter table public.profiles enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.wishlists enable row level security;
alter table public.reviews enable row level security;
alter table public.newsletter_subscribers enable row level security;
alter table public.contact_messages enable row level security;

-- catalog: public read of active items, admin full access
drop policy if exists categories_read on public.categories;
create policy categories_read on public.categories for select using (true);
drop policy if exists categories_admin on public.categories;
create policy categories_admin on public.categories for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists products_read on public.products;
create policy products_read on public.products for select using (is_active or public.is_admin());
drop policy if exists products_admin on public.products;
create policy products_admin on public.products for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists product_images_read on public.product_images;
create policy product_images_read on public.product_images for select
  using (exists (select 1 from public.products p where p.id = product_id and (p.is_active or public.is_admin())));
drop policy if exists product_images_admin on public.product_images;
create policy product_images_admin on public.product_images for all using (public.is_admin()) with check (public.is_admin());

-- coupons: not readable by the public (validated through validate_coupon / place_order)
drop policy if exists coupons_admin on public.coupons;
create policy coupons_admin on public.coupons for all using (public.is_admin()) with check (public.is_admin());

-- profiles
drop policy if exists profiles_self_read on public.profiles;
create policy profiles_self_read on public.profiles for select using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_self_update on public.profiles;
create policy profiles_self_update on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());
drop policy if exists profiles_admin on public.profiles;
create policy profiles_admin on public.profiles for all using (public.is_admin()) with check (public.is_admin());

-- orders: owners read their own; creation only via place_order(); guests have no direct access
drop policy if exists orders_owner_read on public.orders;
create policy orders_owner_read on public.orders for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists orders_admin_write on public.orders;
create policy orders_admin_write on public.orders for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists order_items_owner_read on public.order_items;
create policy order_items_owner_read on public.order_items for select
  using (exists (select 1 from public.orders o where o.id = order_id and (o.user_id = auth.uid() or public.is_admin())));
drop policy if exists order_items_admin_write on public.order_items;
create policy order_items_admin_write on public.order_items for all using (public.is_admin()) with check (public.is_admin());

-- wishlists
drop policy if exists wishlists_own on public.wishlists;
create policy wishlists_own on public.wishlists for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- reviews
drop policy if exists reviews_read on public.reviews;
create policy reviews_read on public.reviews for select using (true);
drop policy if exists reviews_insert on public.reviews;
create policy reviews_insert on public.reviews for insert with check (user_id = auth.uid());
drop policy if exists reviews_update on public.reviews;
create policy reviews_update on public.reviews for update using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists reviews_delete on public.reviews;
create policy reviews_delete on public.reviews for delete using (user_id = auth.uid() or public.is_admin());

-- newsletter / contact: anyone may submit, only admin reads
drop policy if exists newsletter_insert on public.newsletter_subscribers;
create policy newsletter_insert on public.newsletter_subscribers for insert to anon, authenticated with check (true);
drop policy if exists newsletter_admin on public.newsletter_subscribers;
create policy newsletter_admin on public.newsletter_subscribers for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists contact_insert on public.contact_messages;
create policy contact_insert on public.contact_messages for insert to anon, authenticated with check (true);
drop policy if exists contact_admin on public.contact_messages;
create policy contact_admin on public.contact_messages for all using (public.is_admin()) with check (public.is_admin());

-- ---------------------------------------------------------------- RPCs
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

create or replace function public.validate_coupon(p_code text, p_subtotal numeric) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare c public.coupons;
begin
  select * into c from public.coupons where code = upper(trim(coalesce(p_code, '')));
  if not found or not c.active then return jsonb_build_object('valid', false, 'coupon', null, 'reason', 'invalid'); end if;
  if c.expires_at is not null and c.expires_at < now() then
    return jsonb_build_object('valid', false, 'coupon', null, 'reason', 'expired'); end if;
  if not (coalesce(p_subtotal, 0) > c.min_subtotal) then
    return jsonb_build_object('valid', false, 'reason', 'min_subtotal',
      'coupon', jsonb_build_object('code', c.code, 'percent', c.percent, 'min_subtotal', c.min_subtotal)); end if;
  return jsonb_build_object('valid', true, 'reason', null,
    'coupon', jsonb_build_object('code', c.code, 'percent', c.percent, 'min_subtotal', c.min_subtotal));
end $$;
grant execute on function public.validate_coupon(text, numeric) to anon, authenticated;

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

create or replace function public.track_order(order_number text, email text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_id uuid;
begin
  select o.id into v_id from public.orders o
  where upper(o.order_number) = upper(trim(track_order.order_number))
    and lower(o.customer_email) = lower(trim(track_order.email));
  if v_id is null then return null; end if;
  return public.order_json(v_id);
end $$;
grant execute on function public.track_order(text, text) to anon, authenticated;

-- admin: change status; cancelling restocks
create or replace function public.admin_set_order_status(p_order_id uuid, p_status text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare o public.orders;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if p_status not in ('pending','paid','processing','shipped','delivered','cancelled') then raise exception 'validation'; end if;
  select * into o from public.orders where id = p_order_id for update;
  if not found then raise exception 'not_found'; end if;
  if p_status = 'cancelled' and o.status <> 'cancelled' then
    update public.products p set stock = p.stock + i.qty from public.order_items i
      where i.order_id = o.id and p.id = i.product_id;
  end if;
  update public.orders set status = p_status where id = o.id;
  return public.order_json(o.id);
end $$;
grant execute on function public.admin_set_order_status(uuid, text) to authenticated;

-- ================================================================ migration 003 (debit card payments via Stripe)
-- The webhook (service role) is the ONLY writer of payment_status/paid_at/stripe_*; browsers never mark orders paid.
-- (orders policies already restrict writes to admins; processed_stripe_events has RLS on and NO policies = no public access.)
create table if not exists public.processed_stripe_events (
  event_id text primary key,
  type text not null,
  received_at timestamptz not null default now()
);
alter table public.processed_stripe_events enable row level security;
revoke all on public.processed_stripe_events from anon, authenticated;

-- ---------------------------------------------------------------- seed (mirrors js/seed.js)
insert into public.categories (id, slug, name, image, sort_order) values
  ('00000000-0000-4000-8000-000000000001', 'fan-zone', 'Fan Zone', 'assets/img/headband.jpg', 0)
on conflict (slug) do nothing;

insert into public.products (id, slug, name, description, price, category_id, image, images, rating, review_count, stock, is_active, is_popular, tags, created_at) values
 ('00000000-0000-4000-8000-000000000101','haiti-face-tattoo','Haiti Face Tattoo','Show your colors from the first whistle. Skin-safe temporary face tattoos in the blue and red of Haiti, easy to apply and easy to remove. Perfect for match day and fan-zone parties.',7.99,'00000000-0000-4000-8000-000000000001','assets/img/face-tattoo.jpg',array['assets/img/face-tattoo.jpg'],5,0,200,true,true,array['face','tattoo','sticker','match day'],'2026-05-02'),
 ('00000000-0000-4000-8000-000000000102','haiti-headband','Haiti Headband','A soft, stretchy headband in Haiti blue and red. Keeps the sweat out of your eyes and the pride on your head. One size fits most.',9.99,'00000000-0000-4000-8000-000000000001','assets/img/headband.jpg',array['assets/img/headband.jpg'],5,0,150,true,true,array['headband','accessory','blue','red'],'2026-05-03'),
 ('00000000-0000-4000-8000-000000000103','haiti-scarf','Haiti Scarf','Wave it, wear it, sing with it. A collectible supporter scarf in the colors of Haiti, warm, soft and made for the stands.',17.99,'00000000-0000-4000-8000-000000000001','assets/img/scarf.jpg',array['assets/img/scarf.jpg'],5,0,100,true,true,array['scarf','collectible','supporter'],'2026-05-04'),
 ('00000000-0000-4000-8000-000000000104','haiti-thunder-stick','Haiti Thunder Stick','Make some noise for the Grenadiers. Inflatable thunder sticks in Haiti colors: bang them together to lead the chant. Light, durable and fun for the whole crowd.',14.99,'00000000-0000-4000-8000-000000000001','assets/img/thunder-stick.jpg',array['assets/img/thunder-stick.jpg'],5,0,120,true,true,array['noisemaker','thunder stick','chant'],'2026-05-05'),
 ('00000000-0000-4000-8000-000000000105','haiti-flag','Haiti Flag','Proud, bold and ready to fly. A durable Haitian flag with reinforced edges and grommets, for the balcony, the car or the stadium.',12.99,'00000000-0000-4000-8000-000000000001',null,'{}',5,0,80,true,false,array['flag','decor','blue','red'],'2026-05-06'),
 ('00000000-0000-4000-8000-000000000106','haiti-fan-tee','Haiti Fan Tee','A jersey-style fan tee in Haiti blue with red trim. Breathable, comfortable and made to be worn loud on match day.',24.99,'00000000-0000-4000-8000-000000000001',null,'{}',5,0,60,true,false,array['tee','shirt','jersey','apparel'],'2026-05-07'),
 ('00000000-0000-4000-8000-000000000107','haiti-cap','Haiti Cap','A classic adjustable cap with the colors of Haiti. Shade for the sun, pride for the crowd.',15.99,'00000000-0000-4000-8000-000000000001',null,'{}',5,0,70,true,false,array['cap','hat','apparel'],'2026-05-08'),
 ('00000000-0000-4000-8000-000000000108','haiti-wristband-set','Haiti Wristband Set','A set of two sweat-absorbing wristbands in Haiti blue and red. Small piece of gear, big team spirit.',5.99,'00000000-0000-4000-8000-000000000001',null,'{}',5,0,150,true,false,array['wristband','accessory','set'],'2026-05-09')
on conflict (slug) do nothing;

insert into public.coupons (code, percent, min_subtotal, active) values ('HT26', 15, 10, true)
on conflict (code) do nothing;

-- ================================================================ migration 002 (media, 3D jobs, storage, preferences)
-- ---------------------------------------------------------------- columns
alter table public.products add column if not exists media jsonb not null default '[]'::jsonb;
do $$ begin
  alter table public.products add constraint products_media_is_array check (jsonb_typeof(media) = 'array' and jsonb_array_length(media) <= 60);
exception when duplicate_object then null; end $$;

alter table public.profiles add column if not exists preferences jsonb not null default '{}'::jsonb;
do $$ begin
  alter table public.profiles add constraint profiles_preferences_is_object check (jsonb_typeof(preferences) = 'object' and pg_column_size(preferences) < 4096);
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------- 3D jobs
create table if not exists public.product_3d_jobs (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  source_media_id uuid not null,
  result_media_id uuid,
  status text not null default 'queued' check (status in ('queued','processing','succeeded','failed')),
  progress int not null default 0 check (progress between 0 and 100),
  provider text,
  provider_task_id text,
  error text,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists product_3d_jobs_product_idx on public.product_3d_jobs(product_id, created_at desc);
create index if not exists product_3d_jobs_task_idx on public.product_3d_jobs(provider, provider_task_id);

drop trigger if exists product_3d_jobs_touch on public.product_3d_jobs;
create trigger product_3d_jobs_touch before update on public.product_3d_jobs
  for each row execute function public.touch_updated_at();

alter table public.product_3d_jobs enable row level security;
-- admins can see, enqueue (status must be 'queued') and delete jobs. Updates are done by the Edge Function (service role bypasses RLS).
drop policy if exists product_3d_jobs_admin_read on public.product_3d_jobs;
create policy product_3d_jobs_admin_read on public.product_3d_jobs for select using (public.is_admin());
drop policy if exists product_3d_jobs_admin_insert on public.product_3d_jobs;
create policy product_3d_jobs_admin_insert on public.product_3d_jobs for insert
  with check (public.is_admin() and status = 'queued' and provider_task_id is null and result_media_id is null);
drop policy if exists product_3d_jobs_admin_delete on public.product_3d_jobs;
create policy product_3d_jobs_admin_delete on public.product_3d_jobs for delete using (public.is_admin());

-- atomic helper for the Edge Function (service role only): add/replace the generated model on a product.
create or replace function public.apply_generated_model(p_product uuid, p_item jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare cur jsonb; nxt jsonb;
begin
  select media into cur from public.products where id = p_product for update;
  if not found then raise exception 'not_found'; end if;
  -- drop an earlier generated model of the same source image (regenerate) and any entry with the same id (idempotent retry)
  select coalesce(jsonb_agg(m order by (m->>'sort')::int), '[]'::jsonb) into nxt
  from jsonb_array_elements(cur) m
  where not (m->>'id' = p_item->>'id'
     or (m->>'type' = 'model3d' and m->>'source' = 'generated' and m->>'source_media_id' = p_item->>'source_media_id'));
  nxt := nxt || jsonb_build_array(jsonb_set(p_item, '{sort}', to_jsonb(jsonb_array_length(nxt))));
  update public.products set media = nxt where id = p_product;
  return nxt;
end $$;
revoke all on function public.apply_generated_model(uuid, jsonb) from public, anon, authenticated;
grant execute on function public.apply_generated_model(uuid, jsonb) to service_role;

-- ---------------------------------------------------------------- storage
-- Public-read bucket. Hard limits enforced by Storage itself: 50 MB per object and the MIME allow-list.
-- (Per-type limits - image 8 MB, video 50 MB, GLB 30 MB - are enforced by the client, by api.js and by the Edge Function;
--  Storage can only apply ONE size limit per bucket.)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('product-media', 'product-media', true, 52428800,
  array['image/jpeg','image/png','image/webp','video/mp4','video/webm','model/gltf-binary'])
on conflict (id) do update set public = true, file_size_limit = 52428800,
  allowed_mime_types = array['image/jpeg','image/png','image/webp','video/mp4','video/webm','model/gltf-binary'];

-- Anyone may read (public bucket); only admins may write. Generated models are written by the Edge Function (service role).
drop policy if exists product_media_public_read on storage.objects;
create policy product_media_public_read on storage.objects for select
  using (bucket_id = 'product-media');
drop policy if exists product_media_admin_insert on storage.objects;
create policy product_media_admin_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'product-media' and public.is_admin() and (storage.foldername(name))[1] in ('products', 'models'));
drop policy if exists product_media_admin_update on storage.objects;
create policy product_media_admin_update on storage.objects for update to authenticated
  using (bucket_id = 'product-media' and public.is_admin()) with check (bucket_id = 'product-media' and public.is_admin());
drop policy if exists product_media_admin_delete on storage.objects;
create policy product_media_admin_delete on storage.objects for delete to authenticated
  using (bucket_id = 'product-media' and public.is_admin());

-- ---------------------------------------------------------------- seeded media (mirrors js/seed.js)
update public.products p set media = jsonb_build_array(jsonb_build_object(
  'id', '0ed1a000-0000-4000-8000-' || right(p.id::text, 12), 'type', 'image', 'url', p.image, 'poster', null,
  'alt', p.name, 'sort', 0, 'is_cover', true, 'source', 'upload', 'status', 'ready'))
where p.media = '[]'::jsonb and p.image is not null
  and p.id in ('00000000-0000-4000-8000-000000000101','00000000-0000-4000-8000-000000000102',
               '00000000-0000-4000-8000-000000000103','00000000-0000-4000-8000-000000000104');

-- ---------------------------------------------------------------- first admin
-- 1) Sign up on the site with the admin email. 2) Run (replace the email):
--    update public.profiles set is_admin = true where email = 'admin@jpslogistics.me';

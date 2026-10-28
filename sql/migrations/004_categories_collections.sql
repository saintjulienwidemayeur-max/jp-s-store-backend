-- ================================================================ migration 004 (categories as managed collections, featured products)
-- Idempotent. Run in the Supabase SQL editor on an existing database (already merged into schema.sql for new projects).
-- Admin-managed categories: description, optional parent (tree), featured / active flags, sort order.
-- Public can read ACTIVE categories only; only admins write. No keys, no secrets.

-- ---------------------------------------------------------------- columns
alter table public.categories add column if not exists description text not null default '';
alter table public.categories add column if not exists parent_id uuid references public.categories(id) on delete set null;
alter table public.categories add column if not exists is_featured boolean not null default false;
alter table public.categories add column if not exists is_active boolean not null default true;
alter table public.categories add column if not exists updated_at timestamptz not null default now();
do $$ begin
  alter table public.categories add constraint categories_not_own_parent check (parent_id is null or parent_id <> id);
exception when duplicate_object then null; end $$;
do $$ begin
  alter table public.categories add constraint categories_slug_format check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$');
exception when duplicate_object then null; end $$;

alter table public.products add column if not exists is_featured boolean not null default false;

drop trigger if exists categories_touch on public.categories;
create trigger categories_touch before update on public.categories for each row execute function public.touch_updated_at();

-- ---------------------------------------------------------------- indexes
create index if not exists categories_parent_idx on public.categories(parent_id);
create index if not exists categories_active_sort_idx on public.categories(is_active, sort_order);
create index if not exists products_featured_idx on public.products(is_featured) where is_featured;
create index if not exists products_active_category_idx on public.products(is_active, category_id);
create index if not exists products_created_idx on public.products(created_at desc);
create index if not exists products_price_idx on public.products(price);

-- ---------------------------------------------------------------- RLS: public reads active categories, admins write
drop policy if exists categories_read on public.categories;
create policy categories_read on public.categories for select using (is_active or public.is_admin());
drop policy if exists categories_admin on public.categories;
create policy categories_admin on public.categories for all using (public.is_admin()) with check (public.is_admin());

-- ---------------------------------------------------------------- admin RPCs (atomic)
-- Delete a category. If products still use it, p_reassign (another category id) is required and they are moved first.
create or replace function public.admin_delete_category(p_id uuid, p_reassign uuid default null) returns integer
language plpgsql security definer set search_path = public as $$
declare n integer;
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  if not exists (select 1 from public.categories where id = p_id) then raise exception 'not_found'; end if;
  select count(*) into n from public.products where category_id = p_id;
  if n > 0 then
    if p_reassign is null or p_reassign = p_id then raise exception 'validation: category still has % products', n; end if;
    if not exists (select 1 from public.categories where id = p_reassign) then raise exception 'validation: unknown reassign target'; end if;
    update public.products set category_id = p_reassign where category_id = p_id;
  end if;
  delete from public.categories where id = p_id; -- children get parent_id = null (FK on delete set null)
  return n;
end $$;
revoke all on function public.admin_delete_category(uuid, uuid) from public;
grant execute on function public.admin_delete_category(uuid, uuid) to authenticated;

-- Set sort_order from an ordered array of category ids (0..n-1). Ids not listed keep their order after the listed ones.
create or replace function public.admin_reorder_categories(p_ids uuid[]) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'forbidden'; end if;
  update public.categories c set sort_order = o.ord - 1
    from unnest(p_ids) with ordinality as o(id, ord) where c.id = o.id;
  update public.categories c set sort_order = coalesce(array_length(p_ids, 1), 0) + r.rn
    from (select id, row_number() over (order by sort_order, name) as rn from public.categories where id <> all (coalesce(p_ids, '{}'))) r
    where c.id = r.id;
end $$;
revoke all on function public.admin_reorder_categories(uuid[]) from public;
grant execute on function public.admin_reorder_categories(uuid[]) to authenticated;

-- ---------------------------------------------------------------- storage: allow admins to upload category images
drop policy if exists product_media_admin_insert on storage.objects;
create policy product_media_admin_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'product-media' and public.is_admin() and (storage.foldername(name))[1] in ('products', 'models', 'categories'));

-- ---------------------------------------------------------------- honest data: Fan Zone is the only seeded collection
-- First run only: describe + feature Fan Zone and its 4 real products (skipped once an admin has featured anything).
update public.categories set description = 'Show your colors for World Cup 2026: official-style Haitian fan gear for match day.', is_featured = true
  where slug = 'fan-zone' and description = '';
update public.products set is_featured = true
  where id in ('00000000-0000-4000-8000-000000000101','00000000-0000-4000-8000-000000000102',
               '00000000-0000-4000-8000-000000000103','00000000-0000-4000-8000-000000000104')
    and not exists (select 1 from public.products where is_featured);
-- Databases created before this migration may still hold the 4 placeholder extras (flag, tee, cap, wristband) that used to be
-- seeded. They are NOT removed automatically; delete them in the admin if you do not sell them.

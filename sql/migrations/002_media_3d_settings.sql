-- 002: product media (images/videos/3D), 3D generation jobs, storage bucket + policies, profile preferences.
-- Additive and idempotent: safe to run on an existing database (SQL editor). Also merged into sql/schema.sql.

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

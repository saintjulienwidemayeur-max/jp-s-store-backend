# JP's Store — Backend

Supabase backend for the JP's Logistics & More store (separate project from the internal logistics system).

- `sql/schema.sql` — full schema (tables, RLS, RPCs, storage bucket, seed). Run once in the Supabase SQL Editor on a new project. Idempotent.
- `sql/migrations/` — incremental migrations (already merged into `schema.sql`; use them to upgrade an existing database).
- `supabase/functions/create-checkout` — creates a Stripe Checkout Session for an order (amount recomputed from the database).
- `supabase/functions/stripe-webhook` — verifies Stripe signatures and marks orders paid (idempotent).
- `supabase/functions/generate-3d` — image-to-3D jobs (Meshy by default, swappable provider).
- `docs/PAYMENTS.md`, `docs/3D.md` — setup, secrets, deployment, caveats.

## Setup
1. Create a new Supabase project.
2. Run `sql/schema.sql`, then promote your first admin (SQL at the bottom of the file).
3. Set function secrets (never commit them): `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `ALLOWED_ORIGINS`, `MESHY_API_KEY`.
4. Deploy: `supabase functions deploy create-checkout generate-3d` and `supabase functions deploy stripe-webhook --no-verify-jwt`.
5. Put the project URL and anon key in the store repo's `js/config.js`.

The storefront lives in the `Jp-s-Store-` repository.

Status: written and unit-tested against the local data layer only; the SQL and Edge Functions have not yet been run against a real Postgres, Stripe or Meshy. Test with Stripe test mode first.

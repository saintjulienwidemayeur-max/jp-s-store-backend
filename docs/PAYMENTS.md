# Debit card payments (Stripe Checkout)

The store never collects, stores or logs card numbers or CVC. At the last checkout step the customer is redirected to a
**Stripe-hosted Checkout page**. Everything price-related is recomputed on the server from the order in the database.

```
checkout.js ──placeOrder(debit_card, status pending)──▶ Supabase (place_order RPC)
     │
     └─createCardCheckout({order_number,email})──▶ Edge Function create-checkout ──▶ Stripe (coupons + checkout/sessions)
                                                        ◀── {url, mode:'stripe'}
browser ──redirect──▶ Stripe page ──success/cancel──▶ order.html?n=..&e=..&paid=1 | &cancelled=1
Stripe ──webhook (signed)──▶ Edge Function stripe-webhook ──▶ orders.status='paid', payment_status='paid'
```
`order.html` polls the order for up to ~60 s after `?paid=1` (the webhook is the only thing that marks an order paid) and
shows **Paid**, or **Payment cancelled** with a **Try again** button (calls `createCardCheckout` again).

## Setup
1. **Stripe account**: create one at stripe.com, stay in *Test mode* first. **Stripe must support your business country**
   (check stripe.com/global). If the business is in a country Stripe does not support (e.g. Haiti), see "Alternatives".
2. **Database**: run `sql/migrations/003_card_payments.sql` in the Supabase SQL editor (idempotent; also merged into
   `sql/schema.sql`). Adds `orders.payment_status`, `stripe_session_id`, `stripe_payment_intent`, `paid_at`, the
   `processed_stripe_events` table (RLS on, no public access) and lets `place_order` accept `debit_card`.
3. **Secrets** (never in the browser or repo):
   ```
   supabase secrets set STRIPE_SECRET_KEY=sk_test_...
   supabase secrets set ALLOWED_ORIGINS=https://store.jpslogistics.me,http://localhost:8080
   ```
   `ALLOWED_ORIGINS` is the allow-list for the success/cancel redirect URLs.
4. **Deploy**:
   ```
   supabase functions deploy create-checkout
   supabase functions deploy stripe-webhook --no-verify-jwt     # Stripe sends no Supabase JWT; the signature authenticates it
   ```
5. **Webhook**: Stripe Dashboard > Developers > Webhooks > Add endpoint
   `https://<project-ref>.supabase.co/functions/v1/stripe-webhook`, events:
   `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `checkout.session.async_payment_failed`,
   `checkout.session.expired`. Copy the signing secret:
   ```
   supabase secrets set STRIPE_WEBHOOK_SECRET=whsec_...
   ```
   Local testing: `stripe listen --forward-to http://127.0.0.1:54321/functions/v1/stripe-webhook`.
6. In `js/config.js` fill `SUPABASE_URL` / `SUPABASE_ANON_KEY` (public values only). Debit card is already the default method.

## Testing
Test card **4242 4242 4242 4242**, any future expiry, any CVC, any ZIP. Declined card: 4000 0000 0000 0002.
3-D Secure test: 4000 0027 6000 3184. Use *Test mode* keys until a real purchase has gone through end to end.

## Security properties
- Browser only sends `{order_number, email}`; amount, items and discount come from the DB. The discount is a one-off Stripe
  coupon (`amount_off`, `max_redemptions 1`), so the Stripe total equals `orders.total` to the cent; the function refuses to
  create a session if items/discount/total in the DB disagree or Stripe's `amount_total` differs.
- Webhook: HMAC-SHA256 over `${t}.${rawBody}` using `STRIPE_WEBHOOK_SECRET`, constant-time compare, 5 minute timestamp
  tolerance (`supabase/functions/_shared/payments-core.js`, unit-tested); idempotent on the event id; the payment is only
  accepted if `amount_total` equals the order total.
- Wrong email and unknown order number return the same `not_found`.
- No card data is rendered, stored or logged; functions log only Stripe error type/code.
- The local DEMO path (`api.demoMarkPaid`) refuses to run unless `mode === 'local'`.

## Notes
- `payment_method_types: ['card']` shows Stripe's card form. Stripe cannot restrict Checkout to debit-only funding; credit
  cards are accepted too. The UI says "Debit card" as the owner requested.
- Currency is USD. Stripe's minimum charge is $0.50.
- Fees: see stripe.com/pricing for your country. Payouts need a verified bank account in a supported country.

## If Stripe is not available in your country
Keep `PAYMENT_METHODS.debit_card.enabled` as is only when Stripe works. Alternatives that use the same redirect pattern
(replace the HTTP calls in `create-checkout` and the verification in `stripe-webhook`): PayPal Checkout, Adyen, Square,
Paddle / Lemon Squeezy (merchant of record, sell from more countries), local gateways (e.g. MonCash business API for
Haiti). A US/other-country entity (e.g. Stripe Atlas) can also hold the Stripe account; check legal/tax advice first.
Until then set `enabled:false` on `debit_card` and the store falls back to MonCash / Zelle / cash on delivery.

## Local demo mode
Without Supabase config the card option goes to a clearly labelled **DEMO** screen (`order.html?...&demo=1`) with a
"Simulate successful payment (demo)" button; there is no card form. 

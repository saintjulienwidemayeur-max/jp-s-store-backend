// Supabase Edge Function (Deno): Stripe webhook endpoint.
//
// Verifies the Stripe-Signature header (HMAC-SHA256 over `${t}.${rawBody}`, 5 min tolerance) BEFORE trusting anything,
// is idempotent on the Stripe event id (table processed_stripe_events), and updates orders with the service role.
//   checkout.session.completed (payment_status=paid) / async_payment_succeeded -> orders.status='paid', payment_status='paid'
//   checkout.session.async_payment_failed -> payment_status='failed';  checkout.session.expired -> payment_status='expired'
//
// Secrets: STRIPE_WEBHOOK_SECRET (whsec_...). Provided automatically: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
// Stripe sends no Supabase JWT, so deploy WITHOUT JWT verification (authenticity comes from the signature):
//   supabase functions deploy stripe-webhook --no-verify-jwt
// Webhook URL: https://<project-ref>.supabase.co/functions/v1/stripe-webhook
// Events to subscribe: checkout.session.completed, checkout.session.async_payment_succeeded,
//   checkout.session.async_payment_failed, checkout.session.expired

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
import { interpretEvent, toCents, verifyStripeSignature } from "../_shared/payments-core.js";

const text = (body: string, status: number) => new Response(body, { status });

Deno.serve(async (req) => {
  if (req.method !== "POST") return text("method not allowed", 405);
  const secret = Deno.env.get("STRIPE_WEBHOOK_SECRET");
  if (!secret) return text("not configured", 503);

  const raw = await req.text(); // RAW body: must not be re-serialised before verification
  const v = await verifyStripeSignature(raw, req.headers.get("stripe-signature"), secret);
  if (!v.ok) { console.error("webhook rejected:", v.reason); return text("invalid signature", 400); }

  let event: any;
  try { event = JSON.parse(raw); } catch { return text("bad json", 400); }
  if (!event?.id || !event?.type) return text("bad event", 400);

  const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });

  // Idempotency: claim the event id first; a duplicate delivery hits the primary key and is acknowledged.
  const claim = await db.from("processed_stripe_events").insert({ event_id: event.id, type: event.type });
  if (claim.error) {
    if (claim.error.code === "23505") return text("duplicate", 200);
    console.error("claim failed", claim.error.code);
    return text("error", 500);
  }

  try {
    const act = interpretEvent(event);
    if (act) {
      const { data: order } = await db.from("orders").select("id, status, payment_status, total, stripe_session_id").eq("id", act.order_id).maybeSingle();
      if (order) {
        if (act.action === "paid") {
          // Defence in depth: only accept a payment that matches the order total exactly.
          if (typeof act.amount_total === "number" && act.amount_total !== toCents(order.total)) {
            console.error("amount mismatch for order", order.id);
          } else if (order.payment_status !== "paid") {
            await db.from("orders").update({
              payment_status: "paid", paid_at: new Date().toISOString(), stripe_payment_intent: act.payment_intent,
              ...(order.status === "pending" ? { status: "paid" } : {}),
            }).eq("id", order.id);
          }
        } else if (order.payment_status !== "paid" && order.stripe_session_id === act.session_id) {
          // only the latest session may mark the order failed/expired (an older, retried session expiring is harmless)
          await db.from("orders").update({ payment_status: act.action }).eq("id", order.id);
        }
      }
    }
    return text("ok", 200);
  } catch (e) {
    console.error("webhook processing failed", (e as Error).message);
    await db.from("processed_stripe_events").delete().eq("event_id", event.id); // let Stripe retry
    return text("error", 500);
  }
});

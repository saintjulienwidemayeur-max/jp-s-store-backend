// Supabase Edge Function (Deno): create a Stripe Checkout Session for an existing, unpaid debit-card order.
//
// The browser sends ONLY { order_number, email, origin? }. Amounts, items and discount are re-read from the DB
// (service role) and sent to Stripe in cents; nothing price-related is trusted from the client.
// Card data never touches this project: the customer is redirected to Stripe's hosted page (session.url).
//
// Secrets (supabase secrets set ...), NEVER in the browser or the repo:
//   STRIPE_SECRET_KEY   sk_test_... / sk_live_... (Stripe secret or restricted key with Checkout Sessions + Coupons write)
//   ALLOWED_ORIGINS     comma-separated site origins allowed for success/cancel URLs, e.g. https://store.jpslogistics.me
// Provided automatically by Supabase: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
// Deploy: supabase functions deploy create-checkout   (JWT verification on; the browser sends the anon key)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
import { buildAmounts, couponParams, pickOrigin, returnUrls, sessionParams } from "../_shared/payments-core.js";

const STRIPE_API = "https://api.stripe.com/v1";
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

async function stripe(path: string, body: URLSearchParams, key: string, idem?: string) {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (idem) headers["Idempotency-Key"] = idem;
  const res = await fetch(`${STRIPE_API}${path}`, { method: "POST", headers, body });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Log Stripe's error type/code only (never request bodies).
    console.error("stripe error", path, res.status, data?.error?.type, data?.error?.code);
    throw new Error("stripe_error");
  }
  return data;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const key = Deno.env.get("STRIPE_SECRET_KEY");
  if (!key) return json({ error: "not_configured" }, 503); // the storefront falls back to the demo screen
  const allowed = Deno.env.get("ALLOWED_ORIGINS");
  if (!allowed) return json({ error: "not_configured" }, 503);

  let input: { order_number?: string; email?: string; origin?: string };
  try { input = await req.json(); } catch { return json({ error: "validation" }, 400); }
  const orderNumber = String(input.order_number || "").trim().toUpperCase();
  const email = String(input.email || "").trim().toLowerCase();
  if (!orderNumber || !email) return json({ error: "validation" }, 400);

  const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });
  const { data: order } = await db.from("orders")
    .select("id, order_number, status, payment_method, payment_status, customer_email, subtotal, discount, shipping, total")
    .eq("order_number", orderNumber).eq("customer_email", email).maybeSingle();
  // Same answer for "no such order" and "wrong email" (no order enumeration).
  if (!order) return json({ error: "not_found" }, 404);
  if (order.payment_method !== "debit_card") return json({ error: "validation" }, 400);
  if (order.payment_status === "paid" || order.status !== "pending") return json({ error: "already_paid", status: order.status }, 409);

  const { data: items } = await db.from("order_items").select("name, unit_price, qty").eq("order_id", order.id);
  let amounts;
  try { amounts = buildAmounts(order, items || []); } catch (e) {
    console.error("amount mismatch", order.order_number, (e as Error).message);
    return json({ error: "validation" }, 422);
  }

  const origin = pickOrigin(input.origin, allowed)!;
  const { successUrl, cancelUrl } = returnUrls(origin, order.order_number, order.customer_email);

  try {
    let couponId: string | undefined;
    if (amounts.discountCents > 0) {
      const c = await stripe("/coupons", couponParams({ discountCents: amounts.discountCents, orderNumber: order.order_number, orderId: order.id }), key);
      couponId = c.id;
    }
    const session = await stripe("/checkout/sessions", sessionParams({ order, amounts, couponId, successUrl, cancelUrl }), key);
    if (typeof session.amount_total === "number" && session.amount_total !== amounts.totalCents) {
      console.error("stripe total differs from order total", order.order_number);
      return json({ error: "validation" }, 422);
    }
    await db.from("orders").update({ stripe_session_id: session.id }).eq("id", order.id);
    return json({ url: session.url, mode: "stripe" });
  } catch {
    return json({ error: "payment_provider_error" }, 502);
  }
});

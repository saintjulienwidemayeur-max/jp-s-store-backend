// Pure payment helpers shared by the Edge Functions (Deno) and the unit tests (Node). No I/O, no secrets.
// Uses only Web APIs (crypto.subtle, TextEncoder, URLSearchParams) available in both runtimes.

export const SIGNATURE_TOLERANCE_SECONDS = 300; // Stripe's default replay window

/** dollars (number|string, as stored in numeric(10,2)) -> integer cents, without float drift */
export function toCents(amount) {
  const n = Number(amount);
  if (!Number.isFinite(n)) throw new Error('invalid amount');
  return Math.round((Math.abs(n) + Number.EPSILON) * 100) * (n < 0 ? -1 : 1);
}

/**
 * Build Checkout amounts from a DB order. Everything is derived from the stored order, never from the client.
 * order: {subtotal, discount, shipping, total}; items: [{name, unit_price, qty}]
 * Returns {lineItems:[{name,unit_amount,quantity}], discountCents, totalCents}
 * Invariant: sum(unit_amount*quantity) - discountCents === totalCents === toCents(order.total)  (shipping is always 0).
 */
export function buildAmounts(order, items) {
  if (!Array.isArray(items) || !items.length) throw new Error('order has no items');
  const lineItems = items.map((i) => {
    const qty = Number(i.qty);
    if (!Number.isInteger(qty) || qty < 1) throw new Error('invalid quantity');
    return { name: String(i.name || 'Item').slice(0, 250), unit_amount: toCents(i.unit_price), quantity: qty };
  });
  const itemsCents = lineItems.reduce((s, l) => s + l.unit_amount * l.quantity, 0);
  const totalCents = toCents(order.total);
  if (toCents(order.shipping || 0) !== 0) throw new Error('shipping must be 0');
  const discountCents = itemsCents - totalCents;
  if (discountCents < 0 || discountCents !== toCents(order.discount || 0)) throw new Error('order totals do not match its items');
  if (totalCents < 50) throw new Error('total below the minimum card charge');
  return { lineItems, discountCents, totalCents };
}

/** x-www-form-urlencoded body for POST /v1/coupons (one-off fixed-amount coupon). */
export function couponParams({ discountCents, orderNumber, orderId }) {
  const p = new URLSearchParams();
  p.set('amount_off', String(discountCents));
  p.set('currency', 'usd');
  p.set('duration', 'once');
  p.set('max_redemptions', '1');
  p.set('name', `Discount ${orderNumber}`.slice(0, 40));
  p.set('metadata[order_id]', orderId);
  return p;
}

/** x-www-form-urlencoded body for POST /v1/checkout/sessions */
export function sessionParams({ order, amounts, couponId, successUrl, cancelUrl }) {
  const p = new URLSearchParams();
  p.set('mode', 'payment');
  p.set('success_url', successUrl);
  p.set('cancel_url', cancelUrl);
  p.set('client_reference_id', order.id);
  p.set('customer_email', order.customer_email);
  p.set('payment_method_types[0]', 'card');
  amounts.lineItems.forEach((l, i) => {
    p.set(`line_items[${i}][quantity]`, String(l.quantity));
    p.set(`line_items[${i}][price_data][currency]`, 'usd');
    p.set(`line_items[${i}][price_data][unit_amount]`, String(l.unit_amount));
    p.set(`line_items[${i}][price_data][product_data][name]`, l.name);
  });
  if (couponId) p.set('discounts[0][coupon]', couponId);
  p.set('metadata[order_id]', order.id);
  p.set('metadata[order_number]', order.order_number);
  p.set('payment_intent_data[metadata][order_id]', order.id);
  p.set('payment_intent_data[metadata][order_number]', order.order_number);
  return p;
}

/** Pick success/cancel base URL from an allow-list (comma-separated origins). Never trust arbitrary origins. */
export function pickOrigin(requested, allowedCsv) {
  const allowed = String(allowedCsv || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
  if (!allowed.length) return null;
  const r = String(requested || '').trim().replace(/\/+$/, '');
  return allowed.includes(r) ? r : allowed[0];
}
export function returnUrls(origin, orderNumber, email) {
  const q = `n=${encodeURIComponent(orderNumber)}&e=${encodeURIComponent(email)}`;
  return { successUrl: `${origin}/order.html?${q}&paid=1`, cancelUrl: `${origin}/order.html?${q}&cancelled=1` };
}

/* ------------------------------------------------------------------ webhook signature */
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

export async function hmacSha256Hex(secret, message) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}
function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
/** Parse "t=1492774577,v1=abc,v1=def,v0=..." */
export function parseSignatureHeader(header) {
  const out = { t: null, v1: [] };
  for (const part of String(header || '').split(',')) {
    const i = part.indexOf('=');
    if (i < 1) continue;
    const k = part.slice(0, i).trim(); const v = part.slice(i + 1).trim();
    if (k === 't') out.t = v; else if (k === 'v1') out.v1.push(v);
  }
  return out;
}
/**
 * Verify a Stripe-Signature header against the RAW request body: HMAC-SHA256(secret, `${t}.${rawBody}`) must equal
 * a v1 value (constant-time), and |now - t| must be within the tolerance (replay protection).
 * Returns {ok:true} or {ok:false, reason}. Never throws.
 */
export async function verifyStripeSignature(rawBody, header, secret, { tolerance = SIGNATURE_TOLERANCE_SECONDS, now = Date.now() } = {}) {
  try {
    if (!secret) return { ok: false, reason: 'no_secret' };
    const { t, v1 } = parseSignatureHeader(header);
    if (!t || !/^\d+$/.test(t) || !v1.length) return { ok: false, reason: 'malformed_header' };
    const expected = await hmacSha256Hex(secret, `${t}.${rawBody}`);
    if (!v1.some((s) => timingSafeEqualHex(s.toLowerCase(), expected))) return { ok: false, reason: 'bad_signature' };
    if (Math.abs(Math.floor(now / 1000) - Number(t)) > tolerance) return { ok: false, reason: 'timestamp_out_of_tolerance' };
    return { ok: true };
  } catch {
    return { ok: false, reason: 'error' };
  }
}
/** Test helper: produce a valid header for a body. */
export async function signStripePayload(rawBody, secret, t = Math.floor(Date.now() / 1000)) {
  return `t=${t},v1=${await hmacSha256Hex(secret, `${t}.${rawBody}`)}`;
}

/**
 * Decide what a verified event means for an order. Pure; the webhook applies the result.
 * Returns null (ignore) or {order_id, action:'paid'|'failed'|'expired', payment_intent, amount_total}
 */
export function interpretEvent(event) {
  const type = event && event.type;
  const s = event && event.data && event.data.object;
  if (!s || !type) return null;
  const order_id = (s.metadata && s.metadata.order_id) || s.client_reference_id || null;
  if (!order_id) return null;
  const payment_intent = typeof s.payment_intent === 'string' ? s.payment_intent : (s.payment_intent && s.payment_intent.id) || null;
  if (type === 'checkout.session.completed' || type === 'checkout.session.async_payment_succeeded') {
    if (s.payment_status !== 'paid') return null; // delayed method: wait for async_payment_succeeded
    return { order_id, action: 'paid', payment_intent, amount_total: s.amount_total, session_id: s.id };
  }
  if (type === 'checkout.session.async_payment_failed') return { order_id, action: 'failed', payment_intent, session_id: s.id };
  if (type === 'checkout.session.expired') return { order_id, action: 'expired', payment_intent, session_id: s.id };
  return null;
}

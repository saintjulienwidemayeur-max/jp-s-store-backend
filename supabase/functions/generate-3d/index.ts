// Supabase Edge Function (Deno): image -> 3D model (GLB) for product media.
//
// Flow:  admin uploads an image -> api.js inserts a `product_3d_jobs` row (queued) and calls this function
//        { action: "advance", job_id }.  The function is a small state machine that is safe to call repeatedly
//        (the browser re-nudges it from get3DJob()/list3DJobs(), and the provider webhook calls it too):
//          queued     -> claims the job atomically, creates a provider task            -> processing
//          processing -> polls the provider; on success downloads the GLB into Storage
//                        (product-media/models/<product>/<job>.glb), adds a `model3d`
//                        media item to products.media (rpc apply_generated_model)        -> succeeded
//                        on failure                                                       -> failed (+ error)
//        No PROVIDER key configured -> the job succeeds immediately with the on-device "tilt" fallback item
//        (url null, fallback "tilt"), exactly like local mode.
//
// Secrets (supabase secrets set ...), NEVER in the browser or the repo:
//   MESHY_API_KEY            Meshy API key (msy_...). Absent => tilt fallback.
//   MESHY_MODEL              optional, default "meshy-6"
//   PROVIDER_3D              optional, default "meshy" (see `providers` below)
//   WEBHOOK_TOKEN            optional; enables a provider webhook (configure it in the provider dashboard) at
//                            POST <function-url>?token=<WEBHOOK_TOKEN>. Polling via the browser works without it.
// Provided automatically by Supabase: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY.
// Deploy with --no-verify-jwt (the webhook has no JWT; this function verifies the caller itself):
//   supabase functions deploy generate-3d --no-verify-jwt

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

const BUCKET = "product-media";
const MAX_GLB_BYTES = 30 * 1024 * 1024;
const MAX_ATTEMPT_AGE_MS = 60 * 60 * 1000; // give up on a task that has been processing for over an hour

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

/* ------------------------------------------------------------------ provider adapter */
type TaskState = { state: "processing" | "succeeded" | "failed"; progress: number; glbUrl?: string; error?: string };
interface Provider {
  name: string;
  configured(): boolean;
  /** Which source image types the provider accepts. */
  supports(mime: string): boolean;
  createTask(imageUrl: string): Promise<string>;
  getTask(taskId: string): Promise<TaskState>;
}

// Meshy Image-to-3D (https://docs.meshy.ai/en/api/image-to-3d)
//   POST https://api.meshy.ai/openapi/v1/image-to-3d     Authorization: Bearer <key>
//        { image_url, ai_model, should_texture, enable_pbr }   -> { result: "<task id>" }
//   GET  https://api.meshy.ai/openapi/v1/image-to-3d/{id} -> { status: PENDING|IN_PROGRESS|SUCCEEDED|FAILED|CANCELED,
//        progress: 0-100, model_urls: { glb, fbx, obj, usdz, ... }, task_error: { message } }
// image_url must be a publicly reachable .jpg/.jpeg/.png URL (or a base64 data URI). Result URLs are signed and expire
// (assets are retained ~3 days on non-Enterprise plans), which is why we copy the GLB into our own bucket.
const meshy: Provider = {
  name: "meshy",
  configured: () => !!Deno.env.get("MESHY_API_KEY"),
  supports: (mime) => mime === "image/jpeg" || mime === "image/png",
  async createTask(imageUrl) {
    const body: Record<string, unknown> = {
      image_url: imageUrl,
      ai_model: Deno.env.get("MESHY_MODEL") || "meshy-6",
      should_texture: true,
      enable_pbr: true,
    };
    const res = await fetch("https://api.meshy.ai/openapi/v1/image-to-3d", {
      method: "POST",
      headers: { Authorization: `Bearer ${Deno.env.get("MESHY_API_KEY")}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.result) throw new Error(`Meshy create failed (${res.status}): ${data.message || JSON.stringify(data).slice(0, 200)}`);
    return String(data.result);
  },
  async getTask(taskId) {
    const res = await fetch(`https://api.meshy.ai/openapi/v1/image-to-3d/${encodeURIComponent(taskId)}`, {
      headers: { Authorization: `Bearer ${Deno.env.get("MESHY_API_KEY")}` },
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`Meshy status failed (${res.status}): ${data.message || ""}`);
    const progress = Math.max(0, Math.min(100, Number(data.progress) || 0));
    if (data.status === "SUCCEEDED") {
      const glbUrl = data.model_urls?.glb;
      return glbUrl ? { state: "succeeded", progress: 100, glbUrl } : { state: "failed", progress, error: "Provider returned no GLB" };
    }
    if (data.status === "FAILED" || data.status === "CANCELED") {
      return { state: "failed", progress, error: data.task_error?.message || `Meshy task ${String(data.status).toLowerCase()}` };
    }
    return { state: "processing", progress }; // PENDING | IN_PROGRESS
  },
};
// Add other providers (e.g. Tripo) here implementing `Provider`, then set PROVIDER_3D=<name>.
const providers: Record<string, Provider> = { meshy };
const provider = (): Provider => providers[Deno.env.get("PROVIDER_3D") || "meshy"] ?? meshy;

/* ------------------------------------------------------------------ helpers */
const service = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

/** Caller must be an admin (JWT) or present the webhook token. */
async function authorize(req: Request, admin: ReturnType<typeof service>, url: URL): Promise<"admin" | "webhook" | null> {
  const token = Deno.env.get("WEBHOOK_TOKEN");
  if (token && url.searchParams.get("token") === token) return "webhook";
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const { data: u } = await admin.auth.getUser(auth.slice(7));
  if (!u?.user) return null;
  const { data: prof } = await admin.from("profiles").select("is_admin").eq("id", u.user.id).maybeSingle();
  return prof?.is_admin ? "admin" : null;
}

type Job = {
  id: string; product_id: string; source_media_id: string; status: string; progress: number;
  provider: string | null; provider_task_id: string | null; created_at: string; updated_at: string;
};

async function fail(admin: ReturnType<typeof service>, job: Job, message: string) {
  await admin.from("product_3d_jobs").update({ status: "failed", error: message.slice(0, 500) }).eq("id", job.id);
  return { ...job, status: "failed", error: message };
}

async function sourceImage(admin: ReturnType<typeof service>, job: Job) {
  const { data: prod } = await admin.from("products").select("id,name,media").eq("id", job.product_id).maybeSingle();
  const media = Array.isArray(prod?.media) ? prod!.media : [];
  const src = media.find((m: any) => m.id === job.source_media_id && m.type === "image");
  return { prod, src };
}

async function finishWith(admin: ReturnType<typeof service>, job: Job, prod: any, src: any, glb: { path: string; url: string; size: number } | null) {
  const item: Record<string, unknown> = {
    id: job.id, // deterministic => retries are idempotent
    type: "model3d", url: glb ? glb.url : null, poster: src.url, alt: `${prod.name} (3D)`, sort: 0, is_cover: false,
    source: "generated", status: "ready", source_media_id: src.id, job_id: job.id,
    ...(glb ? { path: glb.path, size: glb.size, mime: "model/gltf-binary" } : { fallback: "tilt" }),
  };
  const { error } = await admin.rpc("apply_generated_model", { p_product: job.product_id, p_item: item });
  if (error) return fail(admin, job, `Could not attach model: ${error.message}`);
  await admin.from("product_3d_jobs").update({ status: "succeeded", progress: 100, result_media_id: job.id, error: null }).eq("id", job.id);
  return { ...job, status: "succeeded", progress: 100, result_media_id: job.id };
}

async function advance(admin: ReturnType<typeof service>, jobId: string) {
  const { data: job } = await admin.from("product_3d_jobs").select("*").eq("id", jobId).maybeSingle();
  if (!job) return { status: 404, body: { error: "not_found" } };
  if (job.status === "succeeded" || job.status === "failed") return { status: 200, body: job };
  const p = provider();

  if (job.status === "queued") {
    // Atomic claim so two concurrent calls cannot create two (paid) provider tasks.
    const { data: claimed } = await admin.from("product_3d_jobs")
      .update({ status: "processing", provider: p.configured() ? p.name : "fallback", progress: 0 })
      .eq("id", job.id).eq("status", "queued").select("*").maybeSingle();
    if (!claimed) return { status: 200, body: job }; // someone else is starting it
    const { prod, src } = await sourceImage(admin, claimed);
    if (!prod || !src) return { status: 200, body: await fail(admin, claimed, "Source image not found") };
    if (!p.configured()) return { status: 200, body: await finishWith(admin, claimed, prod, src, null) }; // tilt fallback
    if (!p.supports(src.mime || "")) return { status: 200, body: await fail(admin, claimed, `${p.name} accepts JPEG/PNG sources only`) };
    try {
      const taskId = await p.createTask(src.url);
      await admin.from("product_3d_jobs").update({ provider_task_id: taskId }).eq("id", job.id);
      return { status: 200, body: { ...claimed, provider_task_id: taskId } };
    } catch (e) {
      return { status: 200, body: await fail(admin, claimed, (e as Error).message) };
    }
  }

  // processing
  if (!job.provider_task_id) return { status: 200, body: job }; // being created by the claimer
  if (Date.now() - new Date(job.created_at).getTime() > MAX_ATTEMPT_AGE_MS) return { status: 200, body: await fail(admin, job, "Timed out") };
  let st: TaskState;
  try { st = await p.getTask(job.provider_task_id); } catch (e) { return { status: 200, body: { ...job, warning: (e as Error).message } }; }
  if (st.state === "processing") {
    await admin.from("product_3d_jobs").update({ progress: st.progress }).eq("id", job.id); // also bumps updated_at
    return { status: 200, body: { ...job, progress: st.progress } };
  }
  if (st.state === "failed") return { status: 200, body: await fail(admin, job, st.error || "Generation failed") };

  const { prod, src } = await sourceImage(admin, job);
  if (!prod || !src) return { status: 200, body: await fail(admin, job, "Source image no longer exists") };
  const res = await fetch(st.glbUrl!);
  if (!res.ok) return { status: 200, body: await fail(admin, job, `GLB download failed (${res.status})`) };
  const bytes = new Uint8Array(await res.arrayBuffer());
  if (bytes.length > MAX_GLB_BYTES) return { status: 200, body: await fail(admin, job, "Generated model exceeds 30 MB") };
  const magic = String.fromCharCode(...bytes.slice(0, 4));
  if (magic !== "glTF") return { status: 200, body: await fail(admin, job, "Provider returned an invalid GLB") };
  const path = `models/${job.product_id}/${job.id}.glb`;
  const up = await admin.storage.from(BUCKET).upload(path, bytes, { contentType: "model/gltf-binary", upsert: true, cacheControl: "31536000" });
  if (up.error) return { status: 200, body: await fail(admin, job, `Storage upload failed: ${up.error.message}`) };
  const url = admin.storage.from(BUCKET).getPublicUrl(path).data.publicUrl;
  return { status: 200, body: await finishWith(admin, job, prod, src, { path, url, size: bytes.length }) };
}

/* ------------------------------------------------------------------ entry */
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const admin = service();
  const url = new URL(req.url);
  const who = await authorize(req, admin, url);
  if (!who) return json({ error: "forbidden" }, 403);

  let body: any = {};
  try { body = await req.json(); } catch { /* empty body */ }

  let jobId: string | undefined;
  if (who === "webhook") {
    // Never trust the payload: only use the task id to find our job, then re-query the provider ourselves.
    const taskId = typeof body?.id === "string" ? body.id : undefined;
    if (!taskId) return json({ error: "validation" }, 400);
    const { data: j } = await admin.from("product_3d_jobs").select("id").eq("provider_task_id", taskId).maybeSingle();
    jobId = j?.id;
  } else {
    jobId = typeof body?.job_id === "string" ? body.job_id : undefined;
    if (body?.action !== "advance") return json({ error: "validation" }, 400);
  }
  if (!jobId || !/^[0-9a-f-]{36}$/i.test(jobId)) return json({ error: "validation" }, 400);
  try {
    const r = await advance(admin, jobId);
    return json(r.body, r.status);
  } catch (e) {
    return json({ error: "internal", message: (e as Error).message }, 500);
  }
});

// Consolidated JABIYEN admin auth: context + login + express adapter
// (merged from api.binzeo: admin-context.ts, admin-login.ts, express-adapter.ts)

import "server-only";
import express, { type RequestHandler } from "express";
import { EventEmitter } from "node:events";
import { createRequest, createResponse } from "node-mocks-http";
import { createClient } from "@supabase/supabase-js";

// ---------- admin context ----------
function getJabiyenSupabaseConfig() {
  const url = process.env.JABIYEN_SUPABASE_URL;
  const serviceRoleKey = process.env.JABIYEN_SUPABASE_SERVICE_ROLE_KEY;
  const anonKey = process.env.JABIYEN_SUPABASE_ANON_KEY;
  if (!url || !serviceRoleKey || !anonKey) {
    throw new Error("JABIYEN database environment is not configured");
  }
  return { url, serviceRoleKey, anonKey };
}

let serviceClient;
function getServiceClient() {
  if (!serviceClient) {
    const { url, serviceRoleKey } = getJabiyenSupabaseConfig();
    serviceClient = createClient(url, serviceRoleKey);
  }
  return serviceClient;
}

export const supabase = new Proxy({} as ReturnType<typeof createClient>, {
  get(_target, property) {
    if (property === "then") return undefined;
    if (typeof property === "symbol") return undefined;
    const client = getServiceClient();
    const value = client[property];
    return typeof value === "function" ? value.bind(client) : value;
  },
});

export function createJabiyenAuthClient() {
  const { url, anonKey } = getJabiyenSupabaseConfig();
  return createClient(url, anonKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
      detectSessionInUrl: false,
    },
  });
}

export async function getJabiyenAdmin(userId) {
  return supabase
    .from("admins")
    .select("id,user_id,email,full_name,role,is_active")
    .eq("user_id", userId)
    .maybeSingle();
}

export async function adminAuth(req, res, next) {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!token) return res.status(401).json({ success: false, error: "JABIYEN admin session required" });

    const authClient = createJabiyenAuthClient();
    const { data: { user }, error: authError } = await authClient.auth.getUser(token);
    if (authError || !user) return res.status(401).json({ success: false, error: "Invalid JABIYEN admin session" });

    const { data: admin, error: adminError } = await getJabiyenAdmin(user.id);
    if (adminError) return res.status(503).json({ success: false, error: "Could not verify JABIYEN admin access" });
    if (!admin || admin.is_active !== true) {
      return res.status(403).json({ success: false, error: "Active JABIYEN admin access required" });
    }

    req.user = user;
    req.admin = admin;
    next();
  } catch {
    return res.status(500).json({ success: false, error: "Could not verify JABIYEN admin session" });
  }
}

export async function superAdminAuth(req, res, next) {
  await adminAuth(req, res, () => {
    if (req.admin?.role !== "super_admin") {
      return res.status(403).json({ success: false, error: "JABIYEN super admin access required" });
    }
    next();
  });
}

// ---------- admin login ----------
export const adminLoginRouter = express.Router();

adminLoginRouter.post("/api/admin/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (!email || !password) return res.status(422).json({ success: false, error: "Admin email and password are required" });
    const authClient = createJabiyenAuthClient();
    const { data, error } = await authClient.auth.signInWithPassword({ email, password });
    if (error || !data.user || !data.session) return res.status(401).json({ success: false, error: "Invalid admin email or password" });
    const { data: admin, error: adminError } = await getJabiyenAdmin(data.user.id);
    if (adminError) return res.status(503).json({ success: false, error: "Could not verify JABIYEN admin access" });
    if (!admin || admin.is_active !== true) return res.status(403).json({ success: false, error: "Active JABIYEN admin access required" });
    return res.json({ success: true, data: { session: data.session, user: data.user, admin } });
  } catch (error) {
    return res.status(500).json({ success: false, error: error?.message || "Admin login failed" });
  }
});

adminLoginRouter.get("/api/admin/session", adminAuth, (req, res) => {
  res.json({
    success: true,
    data: {
      user: { id: req.user.id, email: req.user.email },
      admin: { id: req.admin.id, email: req.admin.email, full_name: req.admin.full_name, role: req.admin.role },
    },
  });
});

// ---------- express adapter ----------
export async function runJabiyenGateway(
  handler: RequestHandler,
  request: Request,
  prefix: "/api/jabiyen-public" | "/api/jabiyen-admin",
  path: string[],
) {
  const body = await request.text();
  if (Buffer.byteLength(body, "utf8") > 64 * 1024) {
    return Response.json({ success: false, error: "Request body is too large." }, { status: 413, headers: { "Cache-Control": "no-store" } });
  }
  let parsedBody: unknown;
  if (body) {
    try {
      parsedBody = JSON.parse(body);
    } catch {
      return Response.json({ success: false, error: "Request body must be valid JSON." }, { status: 400, headers: { "Cache-Control": "no-store" } });
    }
  }
  const routePath = path[0] === "api" ? path.slice(1) : path;
  const url = `${prefix}/${routePath.join("/")}${new URL(request.url).search}`;
  const incomingHeaders = Object.fromEntries(request.headers.entries());
  delete incomingHeaders["content-length"];
  delete incomingHeaders["transfer-encoding"];
  const incoming = createRequest({
    method: request.method as never,
    url,
    originalUrl: url,
    headers: incomingHeaders,
    body: parsedBody as never,
  });
  const outgoing = createResponse({ eventEmitter: EventEmitter });

  await new Promise<void>((resolve, reject) => {
    outgoing.on("end", resolve);
    outgoing.on("finish", resolve);
    try {
      handler(incoming as never, outgoing as never, (error?: unknown) => error ? reject(error) : resolve());
    } catch (error) {
      reject(error);
    }
  });

  if (!outgoing._isEndCalled()) {
    return Response.json({ success: false, error: "JABIYEN admin route not found." }, { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  const raw = outgoing._getData();
  const status = outgoing.statusCode || 200;
  const headers = new Headers();
  const responseHeaders = outgoing._getHeaders();
  for (const [key, value] of Object.entries(responseHeaders)) headers.set(key, String(value));
  headers.set("Cache-Control", "no-store");
  return new Response(raw || null, { status, headers });
}
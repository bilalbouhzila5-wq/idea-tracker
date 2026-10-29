import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";

const STATUSES = ["new", "under review", "approved", "rejected"];
const ROLES = ["submitter", "reviewer", "admin"];
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
const bad = (m, s = 400) => json({ error: m }, s);
const rid = () => Date.now().toString(36) + randomBytes(4).toString("hex");
const clean = (s, n) => String(s ?? "").trim().slice(0, n);
const okId = s => /^[a-z0-9]{1,40}$/.test(String(s));

export default async (req) => {
  const store = getStore({ name: "iit", consistency: "strong" });
  const path = new URL(req.url).pathname.replace(/^\/api\//, "").replace(/\/$/, "");
  let b = {};
  if (req.method === "POST") { try { b = await req.json(); } catch { return bad("Invalid request"); } }

  const keys = async prefix => (await store.list({ prefix })).blobs.map(x => x.key);
  const list = async prefix => (await Promise.all((await keys(prefix)).map(k => store.get(k, { type: "json" })))).filter(Boolean);
  const getJ = k => store.get(k, { type: "json" });
  const pub = u => ({ id: u.id, username: u.username, role: u.role });
  const newSession = async uid => { const t = randomBytes(24).toString("hex"); await store.setJSON("sess:" + t, { uid }); return t; };

  const token = (req.headers.get("authorization") || "").replace(/^Bearer /, "");
  const sess = /^[a-f0-9]{48}$/.test(token) ? await getJ("sess:" + token) : null;
  const me = sess ? await getJ("user:" + sess.uid) : null;
  const staff = me && ["reviewer", "admin"].includes(me.role);
  const admin = me?.role === "admin";

  if (path === "signup") {
    const email = clean(b.email, 120).toLowerCase(), username = clean(b.username, 40), pw = String(b.password || "");
    if (!/^\S+@\S+\.\S+$/.test(email) || pw.length < 6 || !username) return bad("Enter a username, a valid email and a password of 6+ characters.");
    if (await store.get("email:" + email)) return bad("This email is already registered.");
    const first = (await keys("user:")).length === 0;
    const salt = randomBytes(16).toString("hex");
    const u = { id: rid(), username, email, salt, hash: scryptSync(pw, salt, 32).toString("hex"), role: first ? "admin" : "submitter" };
    await store.setJSON("user:" + u.id, u);
    await store.set("email:" + email, u.id);
    return json({ token: await newSession(u.id), first, user: pub(u) });
  }

  if (path === "login") {
    const id = await store.get("email:" + clean(b.email, 120).toLowerCase());
    const u = id ? await getJ("user:" + id) : null;
    if (!u) return bad("Wrong email or password.", 401);
    const h = scryptSync(String(b.password || ""), u.salt, 32), real = Buffer.from(u.hash, "hex");
    if (h.length !== real.length || !timingSafeEqual(h, real)) return bad("Wrong email or password.", 401);
    return json({ token: await newSession(u.id), user: pub(u) });
  }

  if (path === "state") {
    const [users, ideas, votes, comments] = await Promise.all([list("user:"), list("idea:"), list("vote:"), list("comment:")]);
    return json({ session: me?.id || null, users: users.map(pub), ideas, votes, comments });
  }

  if (!me) return bad("Please log in.", 401);

  if (path === "idea") {
    const title = clean(b.title, 120), description = clean(b.description, 3000), category = clean(b.category, 40);
    if (!title || !description || !category) return bad("Add a title, a description and a category.");
    const idea = { id: rid(), title, description, category, status: "new", submitter_id: me.id, created_at: new Date().toISOString() };
    await store.setJSON("idea:" + idea.id, idea);
    return json({ ok: true });
  }

  if (path === "vote") {
    if (!okId(b.idea_id)) return bad("Unknown idea.", 404);
    const idea = await getJ("idea:" + b.idea_id);
    if (!idea) return bad("Unknown idea.", 404);
    if (idea.submitter_id === me.id) return bad("You can’t vote on your own idea.", 403);   // the rule
    const type = b.type === -1 ? -1 : 1, key = `vote:${idea.id}:${me.id}`;
    const ex = await getJ(key);
    if (ex && ex.vote_type === type) await store.delete(key);
    else await store.setJSON(key, { idea_id: idea.id, user_id: me.id, vote_type: type });
    return json({ ok: true });
  }

  if (path === "comment") {
    if (!okId(b.idea_id) || !(await getJ("idea:" + b.idea_id))) return bad("Unknown idea.", 404);
    const content = clean(b.content, 1000);
    if (!content) return bad("Write a comment first.");
    const parent_id = okId(b.parent_id) ? b.parent_id : null;
    const c = { id: rid(), idea_id: b.idea_id, user_id: me.id, parent_id, content, created_at: new Date().toISOString() };
    await store.setJSON(`comment:${c.idea_id}:${c.id}`, c);
    return json({ ok: true });
  }

  if (path === "status") {
    if (!staff) return bad("Only reviewers and admins can do this.", 403);
    const idea = okId(b.idea_id) ? await getJ("idea:" + b.idea_id) : null;
    if (!idea || !STATUSES.includes(b.status)) return bad("Invalid request.");
    idea.status = b.status;
    await store.setJSON("idea:" + idea.id, idea);
    return json({ ok: true });
  }

  if (path === "delete") {
    if (b.kind === "idea" && okId(b.id)) {
      const idea = await getJ("idea:" + b.id);
      if (!idea) return json({ ok: true });
      if (idea.submitter_id !== me.id && !admin) return bad("Not allowed.", 403);
      const gone = [...(await keys(`vote:${idea.id}:`)), ...(await keys(`comment:${idea.id}:`)), "idea:" + idea.id];
      await Promise.all(gone.map(k => store.delete(k)));
      return json({ ok: true });
    }
    if (b.kind === "comment" && okId(b.id) && okId(b.idea_id)) {
      const all = await list(`comment:${b.idea_id}:`);
      const c = all.find(x => x.id === b.id);
      if (!c) return json({ ok: true });
      if (c.user_id !== me.id && !admin) return bad("Not allowed.", 403);
      const ids = new Set([c.id]);
      for (let n = 0; n < 20; n++) all.forEach(x => { if (ids.has(x.parent_id)) ids.add(x.id); });
      await Promise.all([...ids].map(i => store.delete(`comment:${b.idea_id}:${i}`)));
      return json({ ok: true });
    }
    return bad("Invalid request.");
  }

  if (path === "role") {
    if (!admin) return bad("Only admins can change roles.", 403);
    const u = okId(b.user_id) ? await getJ("user:" + b.user_id) : null;
    if (!u || !ROLES.includes(b.role) || u.id === me.id) return bad("Invalid request.");
    u.role = b.role;
    await store.setJSON("user:" + u.id, u);
    return json({ ok: true });
  }

  return bad("Not found.", 404);
};

export const config = { path: "/api/*" };

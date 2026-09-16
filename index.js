// =====================================================
// Medib4 API Worker
// Public endpoints power the quiz app.
// /api/admin/* endpoints power the admin panel (password protected).
// =====================================================

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Password",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
  });
}

function error(message, status = 400) {
  return json({ error: message }, status);
}

function todayKey() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate()
  ).padStart(2, "0")}`;
}

async function hashSecret(text) {
  const data = new TextEncoder().encode("medib4_salt_" + text);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateRecoveryCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I to avoid confusion
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = "";
  for (let i = 0; i < 8; i++) {
    code += chars[bytes[i] % chars.length];
  }
  return code.slice(0, 4) + "-" + code.slice(4);
}

// ============ RATE LIMITING (brute-force protection) ============
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_ATTEMPTS = 6;
const RATE_LIMIT_BLOCK_MS = 15 * 60 * 1000; // 15 minutes

function getClientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

// Pure check — does NOT record anything. Call before doing the real work.
async function isRateLimited(env, key) {
  const row = await env.DB.prepare("SELECT blocked_until FROM rate_limits WHERE key = ?").bind(key).first();
  if (row && row.blocked_until && new Date(row.blocked_until).getTime() > Date.now()) {
    return true;
  }
  return false;
}

// Call after the real attempt completes, with whether it succeeded.
async function recordAttemptResult(env, key, success) {
  const now = Date.now();
  if (success) {
    await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(key).run();
    return;
  }
  const row = await env.DB.prepare("SELECT attempts, window_start FROM rate_limits WHERE key = ?").bind(key).first();
  if (row && now - new Date(row.window_start).getTime() < RATE_LIMIT_WINDOW_MS) {
    const attempts = row.attempts + 1;
    const blockedUntil =
      attempts >= RATE_LIMIT_MAX_ATTEMPTS ? new Date(now + RATE_LIMIT_BLOCK_MS).toISOString() : null;
    await env.DB.prepare("UPDATE rate_limits SET attempts = ?, blocked_until = ? WHERE key = ?")
      .bind(attempts, blockedUntil, key)
      .run();
  } else {
    await env.DB.prepare(
      "INSERT INTO rate_limits (key, attempts, window_start, blocked_until) VALUES (?, 1, ?, NULL) ON CONFLICT(key) DO UPDATE SET attempts = 1, window_start = excluded.window_start, blocked_until = NULL"
    )
      .bind(key, new Date(now).toISOString())
      .run();
  }
}

async function getSecondaryAdminHash(env) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'secondary_admin_password_hash'").first();
  return row ? row.value : null;
}

// Returns { ok, role } where role is 'primary' | 'secondary' | null
async function checkAdminAuth(pass, env) {
  if (!pass) return { ok: false, role: null };
  if (env.ADMIN_PASSWORD && pass === env.ADMIN_PASSWORD) {
    return { ok: true, role: "primary" };
  }
  const secondaryHash = await getSecondaryAdminHash(env);
  if (secondaryHash) {
    const passHash = await hashSecret(pass);
    if (passHash === secondaryHash) {
      return { ok: true, role: "secondary" };
    }
  }
  return { ok: false, role: null };
}

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function performBackup(env) {
  const [courses, questions, users, comments, messages] = await Promise.all([
    env.DB.prepare("SELECT id, title, icon, sort_order FROM courses ORDER BY sort_order").all(),
    env.DB.prepare(
      "SELECT id, course_id, question, options, answer, explanation, sort_order, gender FROM questions ORDER BY course_id, sort_order"
    ).all(),
    env.DB.prepare(
      "SELECT id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at, name_history FROM users"
    ).all(),
    env.DB.prepare("SELECT id, question_id, user_id, name, text, created_at FROM comments").all(),
    env.DB.prepare("SELECT id, user_id, sender, text, created_at FROM messages").all(),
  ]);
  const snapshot = {
    backup_date: new Date().toISOString(),
    courses: courses.results,
    questions: questions.results,
    users: users.results,
    comments: comments.results,
    messages: messages.results,
  };
  const json_str = JSON.stringify(snapshot);
  const key = "backup-" + new Date().toISOString();
  await env.BACKUPS.put(key, json_str, { metadata: { size: json_str.length } });

  // keep only the most recent 8 backups
  const list = await env.BACKUPS.list({ prefix: "backup-" });
  const keys = list.keys.map((k) => k.name).sort();
  if (keys.length > 8) {
    const toDelete = keys.slice(0, keys.length - 8);
    await Promise.all(toDelete.map((k) => env.BACKUPS.delete(k)));
  }
  return key;
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(performBackup(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // ============ PUBLIC: COURSES ============
      if (path === "/api/courses" && method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT id, title, icon FROM courses ORDER BY sort_order ASC"
        ).all();
        return json(results);
      }

      // ============ PUBLIC: QUESTIONS ============
      // GET /api/questions            -> all questions (used by the app to preload everything)
      // GET /api/questions?course=ID  -> questions for one course
      if (path === "/api/questions" && method === "GET") {
        const courseId = url.searchParams.get("course");
        let stmt;
        if (courseId) {
          stmt = env.DB.prepare(
            "SELECT id, course_id, question, options, answer, explanation, gender FROM questions WHERE course_id = ? ORDER BY sort_order ASC"
          ).bind(courseId);
        } else {
          stmt = env.DB.prepare(
            "SELECT id, course_id, question, options, answer, explanation, gender FROM questions ORDER BY course_id, sort_order ASC"
          );
        }
        const { results } = await stmt.all();
        const parsed = results.map((r) => ({ ...r, options: JSON.parse(r.options) }));
        return json(parsed);
      }

      // ============ PUBLIC: COMMENTS ============
      if (path === "/api/comments" && method === "GET") {
        const questionId = url.searchParams.get("question");
        if (!questionId) return error("پارامتر question الزامی است");
        const { results } = await env.DB.prepare(
          "SELECT id, user_id, name, text, created_at FROM comments WHERE question_id = ? ORDER BY id ASC"
        )
          .bind(questionId)
          .all();
        return json(results);
      }

      if (path === "/api/comments" && method === "POST") {
        const body = await readJSON(request);
        if (!body.question_id || !body.text) return error("question_id و text الزامی هستند");
        const name = (body.name || "کاربر").slice(0, 60);
        const text = String(body.text).slice(0, 500);
        const now = new Date().toISOString();
        const res = await env.DB.prepare(
          "INSERT INTO comments (question_id, user_id, name, text, created_at) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(body.question_id, body.user_id || null, name, text, now)
          .run();
        return json({ ok: true, id: res.meta.last_row_id });
      }

      // PUT /api/comments/:id  { user_id, text }  -- user can edit only their own comment
      let m = path.match(/^\/api\/comments\/(\d+)$/);
      if (m && method === "PUT") {
        const body = await readJSON(request);
        const row = await env.DB.prepare("SELECT user_id FROM comments WHERE id = ?").bind(m[1]).first();
        if (!row) return error("نظر پیدا نشد", 404);
        if (!body.user_id || row.user_id !== body.user_id) return error("اجازه ویرایش این نظر را ندارید", 403);
        const text = String(body.text || "").slice(0, 500);
        if (!text) return error("متن نظر الزامی است");
        await env.DB.prepare("UPDATE comments SET text = ? WHERE id = ?").bind(text, m[1]).run();
        return json({ ok: true });
      }

      // DELETE /api/comments/:id?user_id=...  -- user can delete only their own comment
      if (m && method === "DELETE") {
        const userId = url.searchParams.get("user_id");
        const row = await env.DB.prepare("SELECT user_id FROM comments WHERE id = ?").bind(m[1]).first();
        if (!row) return error("نظر پیدا نشد", 404);
        if (!userId || row.user_id !== userId) return error("اجازه حذف این نظر را ندارید", 403);
        await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(m[1]).run();
        return json({ ok: true });
      }

      // ============ PUBLIC: USER PROFILE / STATS ============
      // GET /api/users/:id
      m = path.match(/^\/api\/users\/([^/]+)$/);
      if (m && method === "GET") {
        const id = m[1];
        let row = await env.DB.prepare(
          "SELECT id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at FROM users WHERE id = ?"
        ).bind(id).first();
        if (!row) {
          const now = new Date().toISOString();
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at) VALUES (?, '', 0, 0, 0, 0, 0, ?, ?, ?)"
          )
            .bind(id, todayKey(), now, now)
            .run();
          row = await env.DB.prepare(
            "SELECT id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at FROM users WHERE id = ?"
          ).bind(id).first();
        }
        if (row.day !== todayKey()) {
          await env.DB.prepare(
            "UPDATE users SET correct_today = 0, wrong_today = 0, day = ?, updated_at = ? WHERE id = ?"
          )
            .bind(todayKey(), new Date().toISOString(), id)
            .run();
          row.correct_today = 0;
          row.wrong_today = 0;
          row.day = todayKey();
        }
        return json(row);
      }

      // POST /api/register  { id, name, password }
      // Creates a brand-new account. Fails if the name is already taken (with a password).
      if (path === "/api/register" && method === "POST") {
        const body = await readJSON(request);
        const id = String(body.id || "").slice(0, 100);
        const name = String(body.name || "").trim().slice(0, 60);
        const password = String(body.password || "");
        if (!id || !name || password.length < 6) {
          return error("نام و رمز عبور (حداقل ۶ کاراکتر) الزامی هستند");
        }
        const existingByName = await env.DB.prepare("SELECT id, password_hash FROM users WHERE name = ?").bind(name).first();
        if (existingByName && existingByName.password_hash) {
          return error("این نام قبلاً ثبت شده است.", 409);
        }
        const passwordHash = await hashSecret(password);
        const recoveryCode = generateRecoveryCode();
        const recoveryCodeHash = await hashSecret(recoveryCode);
        const now = new Date().toISOString();
        if (existingByName) {
          // legacy account with this name but no password yet -> claim it
          await env.DB.prepare("UPDATE users SET password_hash = ?, recovery_code_hash = ?, updated_at = ? WHERE id = ?")
            .bind(passwordHash, recoveryCodeHash, now, existingByName.id)
            .run();
          return json({ ok: true, user_id: existingByName.id, recovery_code: recoveryCode });
        }
        const existingById = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(id).first();
        if (existingById) {
          await env.DB.prepare("UPDATE users SET name = ?, password_hash = ?, recovery_code_hash = ?, updated_at = ? WHERE id = ?")
            .bind(name, passwordHash, recoveryCodeHash, now, id)
            .run();
        } else {
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at, name_history, password_hash, recovery_code_hash) VALUES (?, ?, 0, 0, 0, 0, 0, ?, ?, ?, '[]', ?, ?)"
          )
            .bind(id, name, todayKey(), now, now, passwordHash, recoveryCodeHash)
            .run();
        }
        return json({ ok: true, user_id: id, recovery_code: recoveryCode });
      }

      // POST /api/forgot-password  { name, recovery_code, new_password }
      // Self-service password reset using the one-time recovery code shown at signup.
      // Issues a fresh recovery code on success (the old one is single-use).
      if (path === "/api/forgot-password" && method === "POST") {
        const rlKey = "forgot:" + getClientIp(request);
        if (await isRateLimited(env, rlKey)) {
          return error("تلاش‌های زیاد. چند دقیقه دیگر دوباره امتحان کن.", 429);
        }
        const body = await readJSON(request);
        const name = String(body.name || "").trim().slice(0, 60);
        const recoveryCode = String(body.recovery_code || "").trim().toUpperCase();
        const newPassword = String(body.new_password || "");
        if (!name || !recoveryCode) return error("نام و کد بازیابی الزامی هستند");
        if (newPassword.length < 6) return error("رمز جدید باید حداقل ۶ کاراکتر باشد");
        const row = await env.DB.prepare("SELECT id, recovery_code_hash FROM users WHERE name = ?").bind(name).first();
        if (!row || !row.recovery_code_hash) {
          await recordAttemptResult(env, rlKey, false);
          return error("نام یا کد بازیابی اشتباه است.", 404);
        }
        const codeHash = await hashSecret(recoveryCode);
        if (codeHash !== row.recovery_code_hash) {
          await recordAttemptResult(env, rlKey, false);
          return error("نام یا کد بازیابی اشتباه است.", 401);
        }
        await recordAttemptResult(env, rlKey, true);
        const newPasswordHash = await hashSecret(newPassword);
        const newRecoveryCode = generateRecoveryCode();
        const newRecoveryHash = await hashSecret(newRecoveryCode);
        await env.DB.prepare("UPDATE users SET password_hash = ?, recovery_code_hash = ?, updated_at = ? WHERE id = ?")
          .bind(newPasswordHash, newRecoveryHash, new Date().toISOString(), row.id)
          .run();
        return json({ ok: true, user_id: row.id, recovery_code: newRecoveryCode });
      }

      // POST /api/login  { name, password }
      // Logs into an existing account from any device.
      if (path === "/api/login" && method === "POST") {
        const rlKey = "login:" + getClientIp(request);
        if (await isRateLimited(env, rlKey)) {
          return error("تلاش‌های زیاد. چند دقیقه دیگر دوباره امتحان کن.", 429);
        }
        const body = await readJSON(request);
        const name = String(body.name || "").trim().slice(0, 60);
        const password = String(body.password || "");
        if (!name || !password) return error("نام و رمز عبور الزامی هستند");
        const row = await env.DB.prepare("SELECT id, password_hash FROM users WHERE name = ?").bind(name).first();
        if (!row || !row.password_hash) {
          await recordAttemptResult(env, rlKey, false);
          return error("حسابی با این نام پیدا نشد.", 404);
        }
        const passwordHash = await hashSecret(password);
        if (passwordHash !== row.password_hash) {
          await recordAttemptResult(env, rlKey, false);
          return error("رمز عبور اشتباه است.", 401);
        }
        await recordAttemptResult(env, rlKey, true);
        return json({ ok: true, user_id: row.id });
      }

      // POST /api/users/:id/rename  { name, password }
      // Renames an already-authenticated account (password must match its own stored hash).
      m = path.match(/^\/api\/users\/([^/]+)\/rename$/);
      if (m && method === "POST") {
        const id = m[1];
        const body = await readJSON(request);
        const newName = String(body.name || "").trim().slice(0, 60);
        const password = String(body.password || "");
        if (!newName || !password) return error("نام و رمز عبور الزامی هستند");
        const existing = await env.DB.prepare("SELECT id, name, name_history, password_hash FROM users WHERE id = ?").bind(id).first();
        if (!existing || !existing.password_hash) return error("حساب پیدا نشد", 404);
        const passwordHash = await hashSecret(password);
        if (passwordHash !== existing.password_hash) return error("رمز عبور اشتباه است.", 401);
        if (newName !== existing.name) {
          const taken = await env.DB.prepare("SELECT id FROM users WHERE name = ? AND id != ?").bind(newName, id).first();
          if (taken) return error("این نام قبلاً استفاده شده است.", 409);
        }
        let history = [];
        try {
          history = JSON.parse(existing.name_history || "[]");
        } catch {
          history = [];
        }
        const now = new Date().toISOString();
        if (existing.name && existing.name !== newName) {
          history.push({ name: existing.name, changed_at: now });
          if (history.length > 20) history = history.slice(-20);
        }
        await env.DB.prepare("UPDATE users SET name = ?, name_history = ?, updated_at = ? WHERE id = ?")
          .bind(newName, JSON.stringify(history), now, id)
          .run();
        return json({ ok: true });
      }

      // POST /api/users/:id/set-password  { password }
      // One-time migration for legacy accounts (created before passwords existed) to claim a password.
      m = path.match(/^\/api\/users\/([^/]+)\/set-password$/);
      if (m && method === "POST") {
        const id = m[1];
        const body = await readJSON(request);
        const password = String(body.password || "");
        if (password.length < 6) return error("رمز باید حداقل ۶ کاراکتر باشد");
        const existing = await env.DB.prepare("SELECT id, password_hash FROM users WHERE id = ?").bind(id).first();
        if (!existing) return error("حساب پیدا نشد", 404);
        if (existing.password_hash) return error("این حساب قبلاً رمز دارد.", 409);
        const passwordHash = await hashSecret(password);
        await env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
          .bind(passwordHash, new Date().toISOString(), id)
          .run();
        return json({ ok: true });
      }

      // POST /api/users/:id/answer  { correct: true/false, question_id, course_id }
      m = path.match(/^\/api\/users\/([^/]+)\/answer$/);
      if (m && method === "POST") {
        const id = m[1];
        const body = await readJSON(request);
        const correct = !!body.correct;
        const questionId = body.question_id ? String(body.question_id).slice(0, 100) : null;
        const courseId = body.course_id ? String(body.course_id).slice(0, 100) : null;
        const now = new Date().toISOString();
        const USER_COLS =
          "id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at";
        const existing = await env.DB.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).bind(id).first();
        if (!existing) {
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at) VALUES (?, '', 0, 0, 0, 0, 0, ?, ?, ?)"
          )
            .bind(id, todayKey(), now, now)
            .run();
        }
        // reset daily counters if day changed
        const row = await env.DB.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).bind(id).first();
        let correctToday = row.day === todayKey() ? row.correct_today : 0;
        let wrongToday = row.day === todayKey() ? row.wrong_today : 0;

        const delta = correct ? 10 : -5;
        if (correct) {
          correctToday += 1;
        } else {
          wrongToday += 1;
        }

        await env.DB.prepare(
          `UPDATE users SET
            points = points + ?,
            correct_total = correct_total + ?,
            wrong_total = wrong_total + ?,
            correct_today = ?,
            wrong_today = ?,
            day = ?,
            updated_at = ?
           WHERE id = ?`
        )
          .bind(
            delta,
            correct ? 1 : 0,
            correct ? 0 : 1,
            correctToday,
            wrongToday,
            todayKey(),
            now,
            id
          )
          .run();

        if (questionId && courseId) {
          await env.DB.prepare(
            "INSERT INTO answers (user_id, question_id, course_id, correct, created_at) VALUES (?, ?, ?, ?, ?)"
          )
            .bind(id, questionId, courseId, correct ? 1 : 0, now)
            .run();
        }

        const updated = await env.DB.prepare(`SELECT ${USER_COLS} FROM users WHERE id = ?`).bind(id).first();
        return json(updated);
      }

      // GET /api/users/:id/progress -> distinct correctly-answered question ids, grouped by course
      m = path.match(/^\/api\/users\/([^/]+)\/progress$/);
      if (m && method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT DISTINCT question_id, course_id FROM answers WHERE user_id = ? AND correct = 1"
        )
          .bind(m[1])
          .all();
        return json(results);
      }

      // ============ PUBLIC: DIRECT MESSAGES (user <-> admin) ============
      // GET /api/messages?user_id=ID
      if (path === "/api/messages" && method === "GET") {
        const userId = url.searchParams.get("user_id");
        if (!userId) return error("پارامتر user_id الزامی است");
        const { results } = await env.DB.prepare(
          "SELECT id, sender, text, created_at FROM messages WHERE user_id = ? ORDER BY id ASC"
        )
          .bind(userId)
          .all();
        return json(results);
      }

      // POST /api/messages  { user_id, text }  -- sent by the user
      if (path === "/api/messages" && method === "POST") {
        const body = await readJSON(request);
        if (!body.user_id || !body.text) return error("user_id و text الزامی هستند");
        const text = String(body.text).slice(0, 1000);
        const now = new Date().toISOString();
        await env.DB.prepare(
          "INSERT INTO messages (user_id, sender, text, created_at) VALUES (?, 'user', ?, ?)"
        )
          .bind(body.user_id, text, now)
          .run();
        return json({ ok: true });
      }

      // ============ ADMIN: LOGIN CHECK ============
      if (path === "/api/admin/login" && method === "POST") {
        const body = await readJSON(request);
        const auth = await checkAdminAuth(body.password || "", env);
        if (auth.ok) {
          return json({ ok: true, role: auth.role });
        }
        return error("رمز عبور اشتباه است", 401);
      }

      // Everything under /api/admin/* below requires the password header
      if (path.startsWith("/api/admin/")) {
        const adminAuth = await checkAdminAuth(request.headers.get("X-Admin-Password") || "", env);
        if (!adminAuth.ok) {
          return error("دسترسی غیرمجاز", 401);
        }
        const adminRole = adminAuth.role;

        // ---- ADMIN: SECONDARY ADMIN MANAGEMENT (primary only) ----
        if (path === "/api/admin/settings/secondary-admin" && method === "GET") {
          if (adminRole !== "primary") return error("فقط ادمین اصلی اجازه دارد", 403);
          const hash = await getSecondaryAdminHash(env);
          return json({ isSet: !!hash });
        }

        if (path === "/api/admin/settings/secondary-admin" && method === "POST") {
          if (adminRole !== "primary") return error("فقط ادمین اصلی اجازه دارد", 403);
          const b = await readJSON(request);
          if (!b.password || String(b.password).length < 4) {
            return error("رمز باید حداقل ۶ کاراکتر باشد");
          }
          const hash = await hashSecret(String(b.password));
          await env.DB.prepare(
            "INSERT INTO settings (key, value) VALUES ('secondary_admin_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
          )
            .bind(hash)
            .run();
          return json({ ok: true });
        }

        if (path === "/api/admin/settings/secondary-admin" && method === "DELETE") {
          if (adminRole !== "primary") return error("فقط ادمین اصلی اجازه دارد", 403);
          await env.DB.prepare("DELETE FROM settings WHERE key = 'secondary_admin_password_hash'").run();
          return json({ ok: true });
        }

        // ---- ADMIN: BACKUPS (primary only) ----
        if (path === "/api/admin/backups" && method === "GET") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const list = await env.BACKUPS.list({ prefix: "backup-" });
          const items = list.keys
            .map((k) => ({
              key: k.name,
              created_at: k.name.replace("backup-", ""),
              size: k.metadata && k.metadata.size ? k.metadata.size : null,
            }))
            .sort((a, b) => (a.key < b.key ? 1 : -1));
          return json(items);
        }

        m = path.match(/^\/api\/admin\/backups\/(.+)$/);
        if (m && method === "GET") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const data = await env.BACKUPS.get(decodeURIComponent(m[1]));
          if (!data) return error("بکاپ پیدا نشد", 404);
          return new Response(data, {
            headers: { "Content-Type": "application/json; charset=utf-8", ...CORS_HEADERS },
          });
        }

        if (path === "/api/admin/backups/run-now" && method === "POST") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const key = await performBackup(env);
          return json({ ok: true, key });
        }

        // ---- ADMIN: COURSES ----
        if (path === "/api/admin/courses" && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM courses ORDER BY sort_order ASC"
          ).all();
          return json(results);
        }

        if (path === "/api/admin/courses" && method === "POST") {
          const b = await readJSON(request);
          if (!b.id || !b.title) return error("id و title الزامی هستند");
          const maxRow = await env.DB.prepare(
            "SELECT COALESCE(MAX(sort_order), -1) as m FROM courses"
          ).first();
          await env.DB.prepare(
            "INSERT INTO courses (id, title, icon, sort_order) VALUES (?, ?, ?, ?)"
          )
            .bind(b.id, b.title, b.icon || "book-open", maxRow.m + 1)
            .run();
          return json({ ok: true });
        }

        m = path.match(/^\/api\/admin\/courses\/([^/]+)$/);
        if (m && method === "PUT") {
          const b = await readJSON(request);
          await env.DB.prepare("UPDATE courses SET title = ?, icon = ? WHERE id = ?")
            .bind(b.title, b.icon || "book-open", m[1])
            .run();
          return json({ ok: true });
        }

        if (m && method === "DELETE") {
          await env.DB.prepare("DELETE FROM questions WHERE course_id = ?").bind(m[1]).run();
          await env.DB.prepare("DELETE FROM courses WHERE id = ?").bind(m[1]).run();
          return json({ ok: true });
        }

        // ---- ADMIN: QUESTIONS ----
        if (path === "/api/admin/questions" && method === "GET") {
          const courseId = url.searchParams.get("course");
          let stmt;
          if (courseId) {
            stmt = env.DB.prepare(
              "SELECT * FROM questions WHERE course_id = ? ORDER BY sort_order ASC"
            ).bind(courseId);
          } else {
            stmt = env.DB.prepare("SELECT * FROM questions ORDER BY course_id, sort_order ASC");
          }
          const { results } = await stmt.all();
          const parsed = results.map((r) => ({ ...r, options: JSON.parse(r.options) }));
          return json(parsed);
        }

        if (path === "/api/admin/questions" && method === "POST") {
          const b = await readJSON(request);
          if (!b.id || !b.course_id || !b.question || !Array.isArray(b.options)) {
            return error("فیلدهای الزامی: id, course_id, question, options");
          }
          const maxRow = await env.DB.prepare(
            "SELECT COALESCE(MAX(sort_order), -1) as m FROM questions WHERE course_id = ?"
          )
            .bind(b.course_id)
            .first();
          await env.DB.prepare(
            "INSERT INTO questions (id, course_id, question, options, answer, explanation, sort_order, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              b.id,
              b.course_id,
              b.question,
              JSON.stringify(b.options),
              Number(b.answer) || 0,
              b.explanation || null,
              maxRow.m + 1,
              b.gender || null
            )
            .run();
          return json({ ok: true });
        }

        m = path.match(/^\/api\/admin\/questions\/([^/]+)$/);
        if (m && method === "PUT") {
          const b = await readJSON(request);
          await env.DB.prepare(
            "UPDATE questions SET question = ?, options = ?, answer = ?, explanation = ?, gender = ? WHERE id = ?"
          )
            .bind(
              b.question,
              JSON.stringify(b.options || []),
              Number(b.answer) || 0,
              b.explanation || null,
              b.gender || null,
              m[1]
            )
            .run();
          return json({ ok: true });
        }

        if (m && method === "DELETE") {
          await env.DB.prepare("DELETE FROM questions WHERE id = ?").bind(m[1]).run();
          return json({ ok: true });
        }

        // ---- ADMIN: QUESTION STATS (most-missed questions) ----
        if (path === "/api/admin/question-stats" && method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT
               q.id as id,
               q.course_id as course_id,
               q.question as question,
               COALESCE(SUM(CASE WHEN a.correct = 1 THEN 1 ELSE 0 END), 0) as correct_n,
               COALESCE(SUM(CASE WHEN a.correct = 0 THEN 1 ELSE 0 END), 0) as wrong_n
             FROM questions q
             LEFT JOIN answers a ON a.question_id = q.id
             GROUP BY q.id
             HAVING (correct_n + wrong_n) > 0
             ORDER BY (CAST(wrong_n AS REAL) / (correct_n + wrong_n)) DESC, wrong_n DESC`
          ).all();
          return json(results);
        }

        // ---- ADMIN: COMMENTS ----
        if (path === "/api/admin/comments" && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM comments ORDER BY id DESC LIMIT 300"
          ).all();
          return json(results);
        }

        m = path.match(/^\/api\/admin\/comments\/(\d+)$/);
        if (m && method === "DELETE") {
          await env.DB.prepare("DELETE FROM comments WHERE id = ?").bind(m[1]).run();
          return json({ ok: true });
        }

        // ---- ADMIN: USERS (primary admin only — hidden entirely from secondary) ----
        // Lightweight endpoint (id + name only) usable by primary admin to start a new message thread
        if (path === "/api/admin/users-lite" && method === "GET") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const { results } = await env.DB.prepare(
            "SELECT id, name FROM users WHERE name IS NOT NULL AND name != '' ORDER BY name ASC"
          ).all();
          return json(results);
        }

        if (path === "/api/admin/users" && method === "GET") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const { results } = await env.DB.prepare(
            "SELECT id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at, name_history, (password_hash IS NOT NULL) as has_password FROM users ORDER BY points DESC"
          ).all();
          return json(results);
        }

        m = path.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (m && method === "PUT") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const b = await readJSON(request);
          const newName = String(b.name || "").trim().slice(0, 60);
          if (newName) {
            const taken = await env.DB.prepare("SELECT id FROM users WHERE name = ? AND id != ?").bind(newName, m[1]).first();
            if (taken) return error("این نام قبلاً استفاده شده است.", 409);
          }
          await env.DB.prepare(
            "UPDATE users SET name = ?, points = ? WHERE id = ?"
          )
            .bind(newName, Number(b.points) || 0, m[1])
            .run();
          return json({ ok: true });
        }

        if (m && method === "DELETE") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          await env.DB.prepare("DELETE FROM comments WHERE user_id = ?").bind(m[1]).run();
          await env.DB.prepare("DELETE FROM messages WHERE user_id = ?").bind(m[1]).run();
          await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(m[1]).run();
          return json({ ok: true });
        }

        // POST /api/admin/users/:id/reset-password  { new_password }
        // Manual last-resort reset when a user has lost both their password and recovery code.
        m = path.match(/^\/api\/admin\/users\/([^/]+)\/reset-password$/);
        if (m && method === "POST") {
          if (adminRole !== "primary") return error("مسیر پیدا نشد", 404);
          const b = await readJSON(request);
          const newPassword = String(b.new_password || "");
          if (newPassword.length < 6) return error("رمز باید حداقل ۶ کاراکتر باشد");
          const existing = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(m[1]).first();
          if (!existing) return error("کاربر پیدا نشد", 404);
          const newPasswordHash = await hashSecret(newPassword);
          const newRecoveryCode = generateRecoveryCode();
          const newRecoveryHash = await hashSecret(newRecoveryCode);
          await env.DB.prepare("UPDATE users SET password_hash = ?, recovery_code_hash = ?, updated_at = ? WHERE id = ?")
            .bind(newPasswordHash, newRecoveryHash, new Date().toISOString(), m[1])
            .run();
          return json({ ok: true, recovery_code: newRecoveryCode });
        }

        // ---- ADMIN: MESSAGES (primary admin only — hidden entirely from secondary) ----
        if (path.startsWith("/api/admin/messages") && adminRole !== "primary") {
          return error("مسیر پیدا نشد", 404);
        }

        // GET /api/admin/messages -> one row per user with a message thread (latest message + name)
        if (path === "/api/admin/messages" && method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT
               m.user_id as user_id,
               u.name as name,
               (SELECT text FROM messages WHERE user_id = m.user_id ORDER BY id DESC LIMIT 1) as last_text,
               (SELECT sender FROM messages WHERE user_id = m.user_id ORDER BY id DESC LIMIT 1) as last_sender,
               (SELECT created_at FROM messages WHERE user_id = m.user_id ORDER BY id DESC LIMIT 1) as last_at,
               (SELECT COUNT(*) FROM messages WHERE user_id = m.user_id) as total
             FROM messages m
             LEFT JOIN users u ON u.id = m.user_id
             GROUP BY m.user_id
             ORDER BY last_at DESC`
          ).all();
          return json(results);
        }

        // GET /api/admin/messages/:userId -> full thread with one user
        m = path.match(/^\/api\/admin\/messages\/([^/]+)$/);
        if (m && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT id, sender, text, created_at FROM messages WHERE user_id = ? ORDER BY id ASC"
          )
            .bind(m[1])
            .all();
          return json(results);
        }

        // POST /api/admin/messages  { user_id, text }  -- sent by the admin
        if (path === "/api/admin/messages" && method === "POST") {
          const b = await readJSON(request);
          if (!b.user_id || !b.text) return error("user_id و text الزامی هستند");
          const text = String(b.text).slice(0, 1000);
          const now = new Date().toISOString();
          await env.DB.prepare(
            "INSERT INTO messages (user_id, sender, text, created_at) VALUES (?, 'admin', ?, ?)"
          )
            .bind(b.user_id, text, now)
            .run();
          return json({ ok: true });
        }

        return error("مسیر پیدا نشد", 404);
      }

      return error("مسیر پیدا نشد", 404);
    } catch (e) {
      return error("خطای سرور: " + e.message, 500);
    }
  },
};

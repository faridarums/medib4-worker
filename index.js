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

function isAdmin(request, env) {
  const pass = request.headers.get("X-Admin-Password") || "";
  return env.ADMIN_PASSWORD && pass === env.ADMIN_PASSWORD;
}

async function readJSON(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export default {
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
            "SELECT id, course_id, question, options, answer, explanation FROM questions WHERE course_id = ? ORDER BY sort_order ASC"
          ).bind(courseId);
        } else {
          stmt = env.DB.prepare(
            "SELECT id, course_id, question, options, answer, explanation FROM questions ORDER BY course_id, sort_order ASC"
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
          "SELECT id, name, text, created_at FROM comments WHERE question_id = ? ORDER BY id ASC"
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
        await env.DB.prepare(
          "INSERT INTO comments (question_id, user_id, name, text, created_at) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(body.question_id, body.user_id || null, name, text, now)
          .run();
        return json({ ok: true });
      }

      // ============ PUBLIC: USER PROFILE / STATS ============
      // GET /api/users/:id
      let m = path.match(/^\/api\/users\/([^/]+)$/);
      if (m && method === "GET") {
        const id = m[1];
        let row = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
        if (!row) {
          const now = new Date().toISOString();
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at) VALUES (?, '', 0, 0, 0, 0, 0, ?, ?, ?)"
          )
            .bind(id, todayKey(), now, now)
            .run();
          row = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
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

      // POST /api/users/:id  { name }
      m = path.match(/^\/api\/users\/([^/]+)$/);
      if (m && method === "POST") {
        const id = m[1];
        const body = await readJSON(request);
        const name = String(body.name || "").slice(0, 60);
        const now = new Date().toISOString();
        const existing = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(id).first();
        if (existing) {
          await env.DB.prepare("UPDATE users SET name = ?, updated_at = ? WHERE id = ?")
            .bind(name, now, id)
            .run();
        } else {
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at) VALUES (?, ?, 0, 0, 0, 0, 0, ?, ?, ?)"
          )
            .bind(id, name, todayKey(), now, now)
            .run();
        }
        return json({ ok: true });
      }

      // POST /api/users/:id/answer  { correct: true/false }
      m = path.match(/^\/api\/users\/([^/]+)\/answer$/);
      if (m && method === "POST") {
        const id = m[1];
        const body = await readJSON(request);
        const correct = !!body.correct;
        const now = new Date().toISOString();
        const existing = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
        if (!existing) {
          await env.DB.prepare(
            "INSERT INTO users (id, name, points, correct_total, wrong_total, correct_today, wrong_today, day, created_at, updated_at) VALUES (?, '', 0, 0, 0, 0, 0, ?, ?, ?)"
          )
            .bind(id, todayKey(), now, now)
            .run();
        }
        // reset daily counters if day changed
        const row = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
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

        const updated = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
        return json(updated);
      }

      // ============ ADMIN: LOGIN CHECK ============
      if (path === "/api/admin/login" && method === "POST") {
        const body = await readJSON(request);
        if (env.ADMIN_PASSWORD && body.password === env.ADMIN_PASSWORD) {
          return json({ ok: true });
        }
        return error("رمز عبور اشتباه است", 401);
      }

      // Everything under /api/admin/* below requires the password header
      if (path.startsWith("/api/admin/")) {
        if (!isAdmin(request, env)) {
          return error("دسترسی غیرمجاز", 401);
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
            "INSERT INTO questions (id, course_id, question, options, answer, explanation, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              b.id,
              b.course_id,
              b.question,
              JSON.stringify(b.options),
              Number(b.answer) || 0,
              b.explanation || null,
              maxRow.m + 1
            )
            .run();
          return json({ ok: true });
        }

        m = path.match(/^\/api\/admin\/questions\/([^/]+)$/);
        if (m && method === "PUT") {
          const b = await readJSON(request);
          await env.DB.prepare(
            "UPDATE questions SET question = ?, options = ?, answer = ?, explanation = ? WHERE id = ?"
          )
            .bind(
              b.question,
              JSON.stringify(b.options || []),
              Number(b.answer) || 0,
              b.explanation || null,
              m[1]
            )
            .run();
          return json({ ok: true });
        }

        if (m && method === "DELETE") {
          await env.DB.prepare("DELETE FROM questions WHERE id = ?").bind(m[1]).run();
          return json({ ok: true });
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

        // ---- ADMIN: USERS ----
        if (path === "/api/admin/users" && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM users ORDER BY points DESC"
          ).all();
          return json(results);
        }

        m = path.match(/^\/api\/admin\/users\/([^/]+)$/);
        if (m && method === "PUT") {
          const b = await readJSON(request);
          await env.DB.prepare(
            "UPDATE users SET name = ?, points = ? WHERE id = ?"
          )
            .bind(b.name || "", Number(b.points) || 0, m[1])
            .run();
          return json({ ok: true });
        }

        if (m && method === "DELETE") {
          await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(m[1]).run();
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

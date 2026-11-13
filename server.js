const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const crypto = require("crypto");
const path = require("path");

const MONGO_URL = process.env.MONGO_URL || "mongodb://127.0.0.1:27017";

const MEALS = [
  { name: "Breakfast", from: "05:30", to: "09:30" },
  { name: "Lunch",     from: "11:00", to: "14:30" },
  { name: "Dinner",    from: "17:00", to: "20:30" },
];
const currentMeal = () => {
  const t = new Date().toTimeString().slice(0, 5);
  const m = MEALS.find((m) => t >= m.from && t <= m.to);
  return m ? m.name : null;
};
const todayStr = () => new Date().toLocaleDateString("sv");
const nowStr = () => new Date().toLocaleString("sv");
const normId = (s) => String(s || "").trim().toUpperCase();
const normCardUid = (s) => String(s || "").replace(/[^0-9A-Fa-f]/g, "").toUpperCase();

function extractStudentId(raw) {
  if (!raw) return "";
  let str = String(raw).trim();
  // Decode URL if present
  try {
    if (str.startsWith("http://") || str.startsWith("https://")) {
      const u = new URL(str);
      const qId = u.searchParams.get("id") || u.searchParams.get("student_id") || u.searchParams.get("studentId");
      if (qId) return normId(qId);
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length > 0) {
        const last = parts[parts.length - 1];
        if (/^[a-zA-Z0-9_\-]+$/.test(last)) return normId(last);
      }
    }
  } catch {}
  // Decode JSON if present
  if (str.startsWith("{") && str.endsWith("}")) {
    try {
      const obj = JSON.parse(str);
      const val = obj.id || obj.student_id || obj.studentId || obj.uid;
      if (val) return normId(val);
    } catch {}
  }
  // Common key-value prefixes: "ID: DDU1001", "STUDENT=DDU1001"
  const m = str.match(/(?:ID|STUDENT|STUDENT_ID|CARD)[\s:=]+([a-zA-Z0-9\-_/]+)/i);
  if (m && m[1]) return normId(m[1]);

  return normId(str);
}

function hashPw(pw, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString("hex") };
}
function verifyPw(pw, salt, hash) {
  const a = Buffer.from(crypto.scryptSync(pw, salt, 64).toString("hex"));
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

async function main() {
  const client = new MongoClient(MONGO_URL);
  await client.connect();
  const db = client.db("cafeteria");
  const users = db.collection("users");
  const students = db.collection("students");
  const checkins = db.collection("checkins");

  await users.createIndex({ username: 1 }, { unique: true });
  await checkins.createIndex({ student_id: 1, meal: 1, day: 1 }, { unique: true });
  await checkins.createIndex({ day: 1 });
  await students.createIndex({ card_uid: 1 }, { sparse: true });
  await students.createIndex({ nfc_uid: 1 }, { sparse: true });

  const nearbyBroadcasts = new Map(); // studentId -> { id, name, department, year, ts }

  if ((await users.countDocuments()) === 0) {
    const pw = process.env.ADMIN_PASSWORD || "admin123";
    const { salt, hash } = hashPw(pw);
    await users.insertOne({ username: "admin", name: "Administrator", role: "admin", salt, pass_hash: hash, active: true });
    console.log("Created admin account -> username: admin  password:", pw, "(change it!)");
  }

  const sessions = new Map();
  async function getUser(req) {
    const m = /(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
    const s = m && sessions.get(m[1]);
    if (!s) return null;
    const u = await users.findOne({ _id: new ObjectId(s.userId) });
    return u && u.active ? {
      id: String(u._id),
      username: u.username,
      name: u.name,
      role: u.role,
      door: u.door || "Door Station"
    } : null;
  }
  const auth = (...roles) => ah(async (req, res, next) => {
    const u = await getUser(req);
    const isApi = req.originalUrl.startsWith("/api");
    if (!u) return isApi ? res.status(401).json({ error: "Login required" }) : res.redirect("/login.html");
    if (roles.length && !roles.includes(u.role))
      return isApi ? res.status(403).json({ error: "Not allowed" }) : res.redirect("/");
    req.user = u;
    next();
  });

  const app = express();
  app.use(express.json({ limit: "2mb" }));

  app.get("/", ah(async (req, res) => {
    const u = await getUser(req);
    if (!u) return res.redirect("/login.html");
    res.redirect(u.role === "admin" ? "/admin" : "/checker");
  }));
  app.get("/admin", auth("admin"), (req, res) => res.sendFile(path.join(__dirname, "views", "admin.html")));
  app.get("/checker", auth("admin", "checker"), (req, res) => res.sendFile(path.join(__dirname, "views", "checker.html")));
  app.get("/student", (req, res) => res.sendFile(path.join(__dirname, "views", "student.html")));
  app.use(express.static("public"));

  app.post("/api/login", ah(async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const u = await users.findOne({ username });
    if (!u || !u.active || !verifyPw(password, u.salt, u.pass_hash))
      return res.status(401).json({ error: "Wrong username or password" });
    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, { userId: String(u._id) });
    res.setHeader("Set-Cookie", `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200`);
    res.json({ role: u.role });
  }));
  app.post("/api/logout", (req, res) => {
    const m = /(?:^|; )sid=([a-f0-9]+)/.exec(req.headers.cookie || "");
    if (m) sessions.delete(m[1]);
    res.setHeader("Set-Cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
    res.json({ ok: true });
  });
  app.get("/api/me", auth(), (req, res) => res.json(req.user));

  app.get("/api/meals", (req, res) => {
    res.json({
      current: currentMeal(),
      meals: MEALS,
      serverTime: new Date().toTimeString().slice(0, 5),
      today: todayStr()
    });
  });

  app.post("/api/checkin", auth("admin", "checker"), ah(async (req, res) => {
    const rawId = req.body.id || "";
    const rawUid = req.body.uid || "";
    const cleanedId = extractStudentId(rawId);
    const cleanedUid = normId(rawUid);
    const meal = req.body.meal || currentMeal();

    if (!meal) {
      return res.json({
        status: "closed",
        message: "Cafeteria is currently closed outside meal hours.",
        meals: MEALS,
        serverTime: new Date().toTimeString().slice(0, 5)
      });
    }

    const queries = [];
    if (cleanedId) {
      queries.push({ _id: cleanedId }, { card_uid: cleanedId }, { nfc_uid: cleanedId });
      const stripped = normCardUid(cleanedId);
      if (stripped) queries.push({ card_uid: stripped }, { nfc_uid: stripped });
    }
    if (cleanedUid) {
      queries.push({ _id: cleanedUid }, { card_uid: cleanedUid }, { nfc_uid: cleanedUid });
      const stripped = normCardUid(cleanedUid);
      if (stripped) queries.push({ card_uid: stripped }, { nfc_uid: stripped });
    }

    if (queries.length === 0) {
      return res.status(400).json({ error: "No student ID or card UID provided" });
    }

    const s = await students.findOne({ $or: queries });
    if (!s) return res.status(404).json({ status: "unknown", id: cleanedId || cleanedUid, uid: cleanedUid });

    const isNonCafe = s.cafe_status === "non_cafe" || s.is_cafe === false;
    const info = {
      id: s._id,
      name: s.name,
      department: s.department || "",
      year: s.year || "",
      card_uid: s.card_uid || "",
      cafe_status: isNonCafe ? "non_cafe" : "cafe"
    };

    // 1. Check if student is Non-Café (Cannot eat in cafeteria)
    if (isNonCafe) {
      nearbyBroadcasts.delete(s._id);
      return res.status(403).json({
        status: "non_cafe",
        ...info,
        message: "⛔ YOU ARE NON-CAFÉ! You are not registered to eat in the cafeteria."
      });
    }

    // 2. Check if student is already blocked
    if (s.blocked) {
      nearbyBroadcasts.delete(s._id);
      return res.status(403).json({
        status: "blocked",
        ...info,
        reason: s.block_reason || "Attempted duplicate feeding. Blocked by system.",
        blocked_at: s.blocked_at || "",
        message: "STUDENT BLOCKED from cafeteria feeding. Must be resolved by Admin."
      });
    }

    try {
      const door = String(req.body.door || req.user.door || "Door Station").trim();
      await checkins.insertOne({
        student_id: s._id,
        checker_id: req.user.id,
        checker_name: req.user.name,
        checker_username: req.user.username,
        door,
        meal,
        day: todayStr(),
        ts: nowStr()
      });
      nearbyBroadcasts.delete(s._id);
      res.json({ status: "ok", ...info, meal, door });
    } catch (e) {
      if (e.code !== 11000) throw e;
      const dup = await checkins.findOne({ student_id: s._id, meal, day: todayStr() });
      nearbyBroadcasts.delete(s._id);

      // Student took meal twice! Automatically block them from all meals across all doors.
      const firstTime = dup ? dup.ts.slice(11, 16) : "earlier today";
      const firstDoor = dup && dup.door ? ` at ${dup.door}` : "";
      const firstChecker = dup && dup.checker_name ? ` by ${dup.checker_name}` : "";
      const blockReason = `Took ${meal} twice! (First meal at ${firstTime}${firstDoor}${firstChecker}, duplicate attempt at ${nowStr().slice(11, 16)})`;
      await students.updateOne(
        { _id: s._id },
        {
          $set: {
            blocked: true,
            block_reason: blockReason,
            blocked_at: nowStr(),
            blocked_meal: meal
          }
        }
      );

      res.json({
        status: "blocked_now",
        ...info,
        meal,
        prev_ts: dup ? dup.ts : "",
        reason: blockReason,
        message: `🚨 AUTOMATICALLY BLOCKED! Student already took ${meal} at ${firstTime}${firstDoor}. Blocked from feeding until resolved by Admin.`
      });
    }
  }));

  // Nearby presence APIs
  app.post("/api/nearby/broadcast", ah(async (req, res) => {
    const rawId = req.body.id || "";
    const id = extractStudentId(rawId);
    if (!id) return res.status(400).json({ error: "Student ID required" });
    const s = await students.findOne({ $or: [{ _id: id }, { card_uid: id }, { nfc_uid: id }, { nfc_uid: normCardUid(id) }] });
    if (!s) return res.status(404).json({ error: "Student not found in registry" });

    const isNonCafe = s.cafe_status === "non_cafe" || s.is_cafe === false;
    const cafeStatus = isNonCafe ? "non_cafe" : "cafe";

    if (isNonCafe) {
      return res.status(403).json({
        error: "You are registered as NON-CAFÉ. You are not eligible for campus cafeteria meals.",
        non_cafe: true,
        cafe_status: "non_cafe",
        student: { id: s._id, name: s.name, department: s.department, year: s.year, cafe_status: "non_cafe" }
      });
    }

    if (s.blocked) {
      return res.status(403).json({
        error: "Your cafeteria pass is BLOCKED due to duplicate feeding attempt. Contact Admin to resolve.",
        blocked: true,
        reason: s.block_reason,
        student: { id: s._id, name: s.name, department: s.department, year: s.year, blocked: true, reason: s.block_reason, cafe_status: cafeStatus }
      });
    }

    nearbyBroadcasts.set(s._id, {
      id: s._id,
      name: s.name,
      department: s.department || "",
      year: s.year || "",
      cafe_status: cafeStatus,
      ts: Date.now()
    });
    res.json({ ok: true, student: { id: s._id, name: s.name, department: s.department, year: s.year, cafe_status: cafeStatus } });
  }));

  app.get("/api/nearby", auth("admin", "checker"), ah(async (req, res) => {
    const cutoff = Date.now() - 5 * 60 * 1000; // 5 min timeout
    const list = [];
    for (const [id, item] of nearbyBroadcasts.entries()) {
      if (item.ts >= cutoff) {
        list.push({ ...item, ageSec: Math.round((Date.now() - item.ts) / 1000) });
      } else {
        nearbyBroadcasts.delete(id);
      }
    }
    list.sort((a, b) => b.ts - a.ts);
    res.json(list);
  }));

  app.delete("/api/nearby/:id", auth("admin", "checker"), (req, res) => {
    nearbyBroadcasts.delete(normId(req.params.id));
    res.json({ ok: true });
  });

  app.get("/api/students/search", auth("admin", "checker"), ah(async (req, res) => {
    const q = String(req.query.q || "").trim();
    if (!q) return res.json([]);
    const regex = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    const list = await students.find({
      $or: [{ _id: regex }, { name: regex }, { card_uid: regex }, { nfc_uid: regex }]
    }).limit(10).toArray();
    res.json(list.map((s) => ({ id: s._id, name: s.name, department: s.department || "", year: s.year || "", card_uid: s.card_uid || "" })));
  }));

  async function withStudents(rows) {
    const ids = [...new Set(rows.map((r) => r.student_id))];
    const list = await students.find({ _id: { $in: ids } }).toArray();
    const map = new Map(list.map((s) => [s._id, s]));
    return rows.map((r) => {
      const s = map.get(r.student_id);
      return {
        _id: String(r._id),
        ts: r.ts,
        day: r.day,
        meal: r.meal,
        id: r.student_id,
        name: s ? s.name : "?",
        department: s ? (s.department || "-") : "-",
        year: s ? (s.year || "-") : "-",
        cafe_status: s ? (s.cafe_status || "cafe") : "cafe",
        checker_id: r.checker_id,
        door: r.door || "Door Station"
      };
    });
  }

  app.get("/api/checkins/today", auth("admin", "checker"), ah(async (req, res) => {
    const query = { day: todayStr() };

    // Multi-door Checker Privacy & Station Isolation:
    // A checker only sees the students who checked in at their specific station.
    // They never see students checked in by other checkers at other doors.
    if (req.user.role === "checker" || req.query.scope === "me") {
      query.checker_id = req.user.id;
    }
    const rows = await checkins.find(query).sort({ ts: -1 }).limit(100).toArray();
    res.json(await withStudents(rows));
  }));

  app.get("/api/users", auth("admin"), ah(async (req, res) => {
    const list = await users.find({}).sort({ role: 1, name: 1 }).toArray();
    res.json(list.map((u) => ({ id: String(u._id), username: u.username, name: u.name, role: u.role, active: u.active, door: u.door || "" })));
  }));

  app.post("/api/users", auth("admin"), ah(async (req, res) => {
    const username = String(req.body.username || "").trim().toLowerCase();
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");
    const role = req.body.role === "admin" ? "admin" : "checker";
    const door = String(req.body.door || "").trim();
    if (!username || !name || password.length < 6)
      return res.status(400).json({ error: "Username, name and a password of 6+ characters are required" });
    const { salt, hash } = hashPw(password);
    try {
      await users.insertOne({ username, name, role, door, salt, pass_hash: hash, active: true });
      res.json({ ok: true });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "Username already exists" });
      throw e;
    }
  }));

  // Update user / admin account (username, name, role, door, active, and optional password)
  app.put("/api/users/:id", auth("admin"), ah(async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Bad user ID" });
    const u = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!u) return res.status(404).json({ error: "User not found" });

    const newUsername = String(req.body.username || u.username).trim().toLowerCase();
    const newName = String(req.body.name || u.name).trim();
    const newRole = req.body.role ? (req.body.role === "admin" ? "admin" : "checker") : u.role;
    const newActive = req.body.active !== undefined ? Boolean(req.body.active) : u.active;
    const newDoor = req.body.door !== undefined ? String(req.body.door).trim() : (u.door || "");
    const newPassword = String(req.body.password || "").trim();

    if (!newUsername || !newName) {
      return res.status(400).json({ error: "Username and name cannot be empty" });
    }

    if (newUsername !== u.username) {
      const conflict = await users.findOne({ username: newUsername, _id: { $ne: u._id } });
      if (conflict) return res.status(409).json({ error: "Username already taken by another account" });
    }

    // Safety guard: ensure at least one active administrator remains
    if ((u.role === "admin" && newRole !== "admin") || (u.role === "admin" && !newActive)) {
      const adminCount = await users.countDocuments({ role: "admin", active: true, _id: { $ne: u._id } });
      if (adminCount === 0) {
        return res.status(400).json({ error: "Cannot demote or deactivate the last remaining active administrator." });
      }
    }

    const updates = {
      username: newUsername,
      name: newName,
      role: newRole,
      door: newDoor,
      active: newActive
    };

    if (newPassword) {
      if (newPassword.length < 6) return res.status(400).json({ error: "Password must be at least 6 characters" });
      const { salt, hash } = hashPw(newPassword);
      updates.salt = salt;
      updates.pass_hash = hash;
    }

    await users.updateOne({ _id: u._id }, { $set: updates });
    res.json({ ok: true, user: { id: String(u._id), username: newUsername, name: newName, role: newRole, door: newDoor, active: newActive } });
  }));

  // Delete user / admin account
  app.delete("/api/users/:id", auth("admin"), ah(async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Bad user ID" });
    const u = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!u) return res.status(404).json({ error: "User not found" });

    // Safety guard: Cannot delete the last administrator
    if (u.role === "admin") {
      const adminCount = await users.countDocuments({ role: "admin" });
      if (adminCount <= 1) {
        return res.status(400).json({ error: "Cannot delete the only administrator account." });
      }
    }

    // Invalidate sessions for this deleted user
    for (const [token, sess] of sessions.entries()) {
      if (sess.userId === String(u._id)) sessions.delete(token);
    }

    await users.deleteOne({ _id: u._id });
    res.json({ ok: true });
  }));

  app.post("/api/users/:id/toggle", auth("admin"), ah(async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Bad id" });
    const u = await users.findOne({ _id: new ObjectId(req.params.id) });
    if (!u) return res.status(404).json({ error: "User not found" });

    if (u.role === "admin" && u.active) {
      const adminCount = await users.countDocuments({ role: "admin", active: true, _id: { $ne: u._id } });
      if (adminCount === 0) {
        return res.status(400).json({ error: "Cannot disable the only active administrator account." });
      }
    }

    await users.updateOne({ _id: u._id }, [{ $set: { active: { $not: ["$active"] } } }]);
    res.json({ ok: true });
  }));

  app.post("/api/users/:id/password", auth("admin"), ah(async (req, res) => {
    const password = String(req.body.password || "");
    if (password.length < 6) return res.status(400).json({ error: "Password must be 6+ characters" });
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Bad id" });
    const { salt, hash } = hashPw(password);
    await users.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { salt, pass_hash: hash } });
    res.json({ ok: true });
  }));

  app.get("/api/students", auth("admin"), ah(async (req, res) => {
    const list = await students.find({}).sort({ name: 1 }).toArray();
    res.json(list.map((s) => ({
      id: s._id,
      name: s.name,
      department: s.department || "",
      year: s.year || "",
      card_uid: s.card_uid || s.nfc_uid || "",
      cafe_status: (s.cafe_status === "non_cafe" || s.is_cafe === false) ? "non_cafe" : "cafe",
      blocked: !!s.blocked,
      block_reason: s.block_reason || "",
      blocked_at: s.blocked_at || "",
      blocked_meal: s.blocked_meal || ""
    })));
  }));

  app.post("/api/students/:id/toggle-cafe", auth("admin"), ah(async (req, res) => {
    const id = normId(req.params.id);
    const s = await students.findOne({ _id: id });
    if (!s) return res.status(404).json({ error: "Student not found" });
    const currentIsNonCafe = s.cafe_status === "non_cafe" || s.is_cafe === false;
    const nextStatus = currentIsNonCafe ? "cafe" : "non_cafe";
    await students.updateOne({ _id: id }, { $set: { cafe_status: nextStatus, is_cafe: nextStatus === "cafe" } });
    res.json({ ok: true, id, cafe_status: nextStatus });
  }));

  app.post("/api/students/:id/unblock", auth("admin"), ah(async (req, res) => {
    const id = normId(req.params.id);
    await students.updateOne(
      { _id: id },
      {
        $set: { blocked: false, unblocked_at: nowStr(), unblocked_by: req.user.name },
        $unset: { block_reason: "", blocked_at: "", blocked_meal: "" }
      }
    );
    res.json({ ok: true, id });
  }));

  app.post("/api/students/:id/block", auth("admin"), ah(async (req, res) => {
    const id = normId(req.params.id);
    const reason = String(req.body.reason || "Blocked by Administrator").trim();
    await students.updateOne(
      { _id: id },
      {
        $set: {
          blocked: true,
          block_reason: reason,
          blocked_at: nowStr(),
          blocked_by: req.user.name
        }
      }
    );
    res.json({ ok: true, id });
  }));
  app.post("/api/students", auth("admin"), ah(async (req, res) => {
    const id = normId(req.body.id);
    const name = String(req.body.name || "").trim();
    const card_uid = normId(req.body.card_uid);
    const cafe_status = String(req.body.cafe_status || "").toLowerCase().includes("non") ? "non_cafe" : "cafe";
    if (!id || !name) return res.status(400).json({ error: "ID and name required" });
    try {
      await students.insertOne({
        _id: id, name,
        department: String(req.body.department || "").trim(),
        year: String(req.body.year || "").trim(),
        card_uid: card_uid || undefined,
        nfc_uid: normCardUid(card_uid) || undefined,
        cafe_status,
        is_cafe: cafe_status === "cafe",
      });
      res.json({ ok: true });
    } catch (e) {
      if (e.code === 11000) return res.status(409).json({ error: "ID or Card UID already exists" });
      throw e;
    }
  }));
  // Edit student (ID, Name, Department, Year, Card UID, Cafe Status, Block status)
  app.put("/api/students/:id", auth("admin"), ah(async (req, res) => {
    const origId = normId(req.params.id);
    const s = await students.findOne({ _id: origId });
    if (!s) return res.status(404).json({ error: "Student not found" });

    const newId = normId(req.body.id || origId);
    const newName = String(req.body.name || s.name).trim();
    const newDept = String(req.body.department !== undefined ? req.body.department : (s.department || "")).trim();
    const newYear = String(req.body.year !== undefined ? req.body.year : (s.year || "")).trim();
    const rawCard = req.body.card_uid !== undefined ? req.body.card_uid : s.card_uid;
    const newCardUid = normId(rawCard);
    const cafe_status = String(req.body.cafe_status || s.cafe_status || "").toLowerCase().includes("non") ? "non_cafe" : "cafe";
    const blocked = req.body.blocked !== undefined ? Boolean(req.body.blocked) : !!s.blocked;
    const blockReason = blocked ? String(req.body.block_reason || s.block_reason || "Administrative block").trim() : "";

    if (!newId || !newName) {
      return res.status(400).json({ error: "Student ID and name cannot be empty" });
    }

    const docUpdates = {
      name: newName,
      department: newDept,
      year: newYear,
      cafe_status,
      is_cafe: cafe_status === "cafe",
      blocked
    };

    if (newCardUid) {
      docUpdates.card_uid = newCardUid;
      docUpdates.nfc_uid = normCardUid(newCardUid);
    } else {
      docUpdates.card_uid = undefined;
      docUpdates.nfc_uid = undefined;
    }

    if (blocked) {
      docUpdates.block_reason = blockReason;
      if (!s.blocked) {
        docUpdates.blocked_at = nowStr();
        docUpdates.blocked_by = req.user.name;
      }
    }

    if (newId !== origId) {
      const conflict = await students.findOne({ _id: newId });
      if (conflict) return res.status(409).json({ error: `Student ID "${newId}" already exists.` });

      const newDoc = { _id: newId, ...docUpdates };
      if (!blocked) {
        delete newDoc.block_reason;
        delete newDoc.blocked_at;
        delete newDoc.blocked_meal;
      }
      await students.insertOne(newDoc);
      await students.deleteOne({ _id: origId });
      await checkins.updateMany({ student_id: origId }, { $set: { student_id: newId } });
      nearbyBroadcasts.delete(origId);
    } else {
      if (!blocked) {
        await students.updateOne(
          { _id: origId },
          {
            $set: docUpdates,
            $unset: { block_reason: "", blocked_at: "", blocked_meal: "" }
          }
        );
      } else {
        await students.updateOne({ _id: origId }, { $set: docUpdates });
      }
    }

    res.json({ ok: true, id: newId });
  }));

  app.delete("/api/students/:id", auth("admin"), ah(async (req, res) => {
    const id = normId(req.params.id);
    await students.deleteOne({ _id: id });
    nearbyBroadcasts.delete(id);
    res.json({ ok: true });
  }));
  app.post("/api/students/import", auth("admin"), ah(async (req, res) => {
    const ops = [];
    for (const line of String(req.body.csv || "").split(/\r?\n/)) {
      const [rawId, name, department = "", year = "", rawCardUid = "", rawCafe = ""] = line.split(",").map((s) => s.trim());
      const id = normId(rawId);
      const card_uid = normId(rawCardUid);
      const cafe_status = String(rawCafe || "").toLowerCase().includes("non") ? "non_cafe" : "cafe";
      if (id && name && id !== "ID") {
        const doc = { _id: id, name, department, year, cafe_status, is_cafe: cafe_status === "cafe" };
        if (card_uid) { doc.card_uid = card_uid; doc.nfc_uid = normCardUid(card_uid); }
        ops.push({ replaceOne: { filter: { _id: id }, replacement: doc, upsert: true } });
      }
    }
    if (ops.length) await students.bulkWrite(ops);
    res.json({ imported: ops.length });
  }));

  app.get("/api/report", auth("admin"), ah(async (req, res) => {
    const filter = {};
    const from = req.query.from;
    const to = req.query.to;
    const date = req.query.date;
    const meal = req.query.meal;

    if (from && to && /^\d{4}-\d{2}-\d{2}$/.test(from) && /^\d{4}-\d{2}-\d{2}$/.test(to)) {
      filter.day = { $gte: from, $lte: to };
    } else if (date && /^\d{4}-\d{2}-\d{2}$/.test(date)) {
      filter.day = date;
    } else {
      filter.day = todayStr();
    }

    if (meal && ["Breakfast", "Lunch", "Dinner"].includes(meal)) {
      filter.meal = meal;
    }

    const rows = await checkins.find(filter).sort({ ts: -1 }).toArray();
    const named = await withStudents(rows);
    const checkerIds = [...new Set(rows.map((r) => r.checker_id).filter((x) => ObjectId.isValid(x)))].map((x) => new ObjectId(x));
    const cl = await users.find({ _id: { $in: checkerIds } }).toArray();
    const cmap = new Map(cl.map((u) => [String(u._id), u.name]));
    res.json(named.map((r, i) => ({
      ...r,
      checker: cmap.get(rows[i].checker_id) || rows[i].checker_name || "-",
      door: rows[i].door || "Door Station"
    })));
  }));

  // Delete individual checkin log record
  app.delete("/api/checkins/:id", auth("admin"), ah(async (req, res) => {
    if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: "Bad check-in ID" });
    await checkins.deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ ok: true });
  }));

  // Delete / clear all checkins for a date
  app.delete("/api/checkins", auth("admin"), ah(async (req, res) => {
    const day = req.query.date;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day || "")) {
      return res.status(400).json({ error: "Valid date required (YYYY-MM-DD)" });
    }
    const result = await checkins.deleteMany({ day });
    res.json({ ok: true, deletedCount: result.deletedCount });
  }));

  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  });

  app.listen(3000, () => console.log("Running on http://localhost:3000  (MongoDB:", MONGO_URL + ")"));
}

main().catch((e) => { console.error("Could not start:", e.message); process.exit(1); });
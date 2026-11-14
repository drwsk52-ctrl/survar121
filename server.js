/**
 * دروسك بلس — سيرفر آمن
 * - دخول الطلاب بكود اشتراك
 * - جلسات JWT
 * - محتوى من Firebase (عبر السيرفر)
 * - فيديوهات Bunny Stream (Public iframe)
 * - لوحة أدمن محمية
 *
 * متغيرات البيئة المطلوبة:
 *   PORT=3000
 *   JWT_SECRET=غيّر-هذا-لسر-طويل
 *   FIREBASE_DB_URL=https://dr-gamal-374e2-default-rtdb.firebaseio.com
 *   FIREBASE_SERVICE_ACCOUNT=./serviceAccount.json
 *     أو الصق JSON كامل في: FIREBASE_SERVICE_ACCOUNT_JSON
 *   ADMIN_EMAILS=drwsk40@gmail.com
 *   BUNNY_LIBRARY_ID=724564
 *   CORS_ORIGIN=https://drplus-mauve.vercel.app
 */

"use strict";

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

// ---------- إعدادات ----------
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const FIREBASE_DB_URL = (process.env.FIREBASE_DB_URL || "https://dr-gamal-374e2-default-rtdb.firebaseio.com").replace(/\/$/, "");
const ADMIN_EMAILS = String(process.env.ADMIN_EMAILS || "drwsk40@gmail.com")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
// دخول لوحة الأدمن: يوزر + باسورد من البيئة
const ADMIN_USERNAME = String(process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const BUNNY_LIBRARY_ID = process.env.BUNNY_LIBRARY_ID || "724564";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const CODE_LEN = 9;

if (!process.env.JWT_SECRET) {
  console.warn("[warn] JWT_SECRET غير مضبوط — تم توليد سر مؤقت. ضعه في البيئة قبل الإنتاج.");
}

// ---------- Firebase Admin ----------
let admin = null;
let db = null;

function loadServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  }
  const p = process.env.FIREBASE_SERVICE_ACCOUNT || path.join(__dirname, "serviceAccount.json");
  if (fs.existsSync(p)) {
    return JSON.parse(fs.readFileSync(p, "utf8"));
  }
  return null;
}

function initFirebase() {
  const sa = loadServiceAccount();
  if (!sa) {
    console.warn("[warn] مفيش Service Account — السيرفر هيشتغل بوضع محدود (REST عام لو القواعد تسمح).");
    console.warn("[warn] للتشغيل الآمن: حط serviceAccount.json أو FIREBASE_SERVICE_ACCOUNT_JSON");
    return false;
  }
  try {
    admin = require("firebase-admin");
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(sa),
        databaseURL: FIREBASE_DB_URL,
      });
    }
    db = admin.database();
    console.log("[ok] Firebase Admin متصل:", FIREBASE_DB_URL);
    return true;
  } catch (e) {
    console.error("[err] Firebase Admin:", e.message);
    return false;
  }
}

const hasAdmin = initFirebase();

// قراءة/كتابة Firebase
async function fbGet(pathStr) {
  if (db) {
    const snap = await db.ref(pathStr).get();
    return snap.exists() ? snap.val() : null;
  }
  // fallback غير آمن — فقط للتطوير لو القواعد لسه مفتوحة
  const url = `${FIREBASE_DB_URL}/${pathStr.replace(/^\//, "")}.json`;
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error("Firebase GET failed: " + r.status);
  return r.json();
}

async function fbSet(pathStr, value) {
  if (!db) throw new Error("الكتابة تحتاج Service Account");
  await db.ref(pathStr).set(value);
}

async function fbUpdate(pathStr, value) {
  if (!db) throw new Error("الكتابة تحتاج Service Account");
  await db.ref(pathStr).update(value);
}

async function fbRemove(pathStr) {
  if (!db) throw new Error("الحذف يحتاج Service Account");
  await db.ref(pathStr).remove();
}

// ---------- أدوات ----------
function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJwt(payload, expiresSec = 60 * 60 * 24 * 30) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(
    JSON.stringify({
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresSec,
    })
  );
  const data = `${header}.${body}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verifyJwt(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const data = `${h}.${b}`;
  const expect = crypto.createHmac("sha256", JWT_SECRET).update(data).digest("base64url");
  if (s !== expect) return null;
  try {
    const payload = JSON.parse(Buffer.from(b, "base64url").toString("utf8"));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

function getBearer(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice(7).trim();
  return (req.headers["x-session-token"] || "").trim() || null;
}

function jsonError(res, status, message) {
  return res.status(status).json({ success: false, error: message });
}

function makeId(prefix = "i") {
  return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function normCode(v) {
  return String(v || "")
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 1632))
    .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 1776))
    .replace(/\D/g, "")
    .slice(0, CODE_LEN);
}

function expiryMs(v) {
  if (!v) return 0;
  if (typeof v === "number") return v < 1e11 ? v * 1000 : v;
  const n = Date.parse(v);
  if (Number.isFinite(n)) return n;
  const x = Number(v);
  return Number.isFinite(x) ? (x < 1e11 ? x * 1000 : x) : 0;
}

function isTermStudent(s) {
  const values = [s.durationType, s.duration, s.type, s.plan, s.subscriptionType]
    .filter(Boolean)
    .map((x) => String(x).trim().toLowerCase());
  return values.some((v) => ["ترم", "الترم", "term", "semester", "الفصل الدراسي"].includes(v) || v.includes("ترم"));
}

function resolveExpiry(s) {
  if (isTermStudent(s)) {
    // نهاية 1 يناير 2027 بتوقيت مصر
    return new Date("2027-01-01T23:59:59+02:00").getTime();
  }
  return expiryMs(s.expiresAt || s.expiry || s.expires);
}

function isActiveStudent(s) {
  if (!s || typeof s !== "object") return false;
  if (s.active === false) return false;
  const status = String(s.status || "").trim().toLowerCase();
  const bad = ["منتهي", "موقوف", "غير نشط", "غير مفعل", "inactive", "disabled", "expired", "suspended", "stopped"];
  if (s.active !== true && bad.includes(status)) return false;
  const exp = resolveExpiry(s);
  if (exp && exp <= Date.now()) return false;
  return true;
}

function bunnyEmbedUrl(videoIdOrUrl) {
  const raw = String(videoIdOrUrl || "").trim();
  if (!raw) return "";
  // لو رابط كامل
  try {
    const u = new URL(raw);
    if (u.hostname.includes("mediadelivery.net")) {
      u.pathname = u.pathname.replace(/^\/play\//i, "/embed/");
      return u.toString();
    }
    if (/\.(m3u8|mp4)(\?|$)/i.test(u.pathname)) return raw;
  } catch {}
  // لو videoId فقط
  if (/^[0-9a-f-]{30,}$/i.test(raw) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(raw)) {
    return `https://iframe.mediadelivery.net/embed/${BUNNY_LIBRARY_ID}/${raw}`;
  }
  return raw;
}

const BRANCH_ALIASES = {
  scientific_sciences: "science_bio",
  science_bio: "science_bio",
  "علمي علوم": "science_bio",
  "علمى علوم": "science_bio",
  scientific_math: "science_math",
  science_math: "science_math",
  "علمي رياضة": "science_math",
  "علمى رياضة": "science_math",
  literary: "literary",
  أدبي: "literary",
  ادبي: "literary",
  azhar: "azhar",
  أزهر: "azhar",
  ازهر: "azhar",
  baccalaureate: "baccalaureate",
  بكالوريا: "baccalaureate",
};

function normalizeBranch(raw) {
  const t = String(raw || "").trim();
  return BRANCH_ALIASES[t] || t;
}

// ---------- Express ----------
const app = express();
app.set("trust proxy", 1);
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN.split(",").map((s) => s.trim()),
    credentials: true,
  })
);
app.use(express.json({ limit: "2mb" }));

// middleware جلسة طالب
function requireStudent(req, res, next) {
  const tok = getBearer(req);
  const sess = verifyJwt(tok);
  if (!sess || sess.role !== "student") return jsonError(res, 401, "سجّل دخولك أولاً");
  req.student = sess;
  next();
}

// middleware أدمن (JWT أدمن بسيط بعد تسجيل منفصل، أو هيدر سري مؤقت)
function requireAdmin(req, res, next) {
  const tok = getBearer(req);
  const sess = verifyJwt(tok);
  if (sess && sess.role === "admin") {
    req.admin = sess;
    return next();
  }
  // بديل للتطوير: X-Admin-Key
  const key = req.headers["x-admin-key"];
  if (process.env.ADMIN_API_KEY && key && key === process.env.ADMIN_API_KEY) {
    req.admin = { role: "admin", email: "api-key" };
    return next();
  }
  return jsonError(res, 401, "غير مصرح — دخول أدمن مطلوب");
}

// ---------- صحة النظام ----------
app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    firebaseAdmin: hasAdmin,
    bunnyLibrary: BUNNY_LIBRARY_ID,
    time: new Date().toISOString(),
  });
});

// ---------- تسجيل دخول الطالب ----------
app.post("/api/login", async (req, res) => {
  try {
    const code = normCode(req.body?.code);
    if (!/^\d{9}$/.test(code)) return jsonError(res, 400, "اكتب كود صحيح من 9 أرقام");

    // الأكواد تحت جذر القاعدة: /{code}
    const student = await fbGet(code);
    if (!student || typeof student !== "object") {
      return jsonError(res, 401, "الكود غير صحيح");
    }
    if (!isActiveStudent(student)) {
      return jsonError(res, 403, "الكود غير مفعّل أو منتهي الصلاحية");
    }

    const branchRaw = student.branchId || student.section || student.branch || "";
    const branchId = normalizeBranch(branchRaw);
    if (!branchId) return jsonError(res, 403, "الشعبة غير محددة لهذا الكود");

    const name = student.studentName || student.name || "";
    const expiresAt = resolveExpiry(student) || 0;

    const token = signJwt({
      role: "student",
      code,
      name,
      branchId,
      expiresAt,
    });

    // تحديث آخر دخول (لو Service Account موجود)
    try {
      if (hasAdmin) await fbUpdate(code, { lastLoginAt: Date.now() });
    } catch {}

    res.json({
      success: true,
      token,
      student: {
        code,
        name,
        branchId,
        expiresAt,
        maxDevices: student.maxDevices ?? student.deviceLimit ?? null,
        durationType: student.durationType || student.type || student.plan || null,
      },
    });
  } catch (e) {
    console.error("[login]", e.message);
    return jsonError(res, 500, "تعذر التحقق من الكود حاليًا");
  }
});

// بيانات الطالب الحالي
app.get("/api/me", requireStudent, async (req, res) => {
  try {
    const student = await fbGet(req.student.code);
    if (!student) return jsonError(res, 401, "الكود لم يعد موجودًا");
    if (!isActiveStudent(student)) return jsonError(res, 403, "الاشتراك غير صالح");
    res.json({
      success: true,
      student: {
        code: req.student.code,
        name: student.studentName || student.name || req.student.name,
        branchId: normalizeBranch(student.branchId || student.section || student.branch || req.student.branchId),
        expiresAt: resolveExpiry(student),
        active: true,
        maxDevices: student.maxDevices ?? student.deviceLimit ?? null,
        durationType: student.durationType || student.type || student.plan || null,
      },
    });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

// ---------- المحتوى للطالب ----------
app.get("/api/content/subjects", requireStudent, async (req, res) => {
  try {
    const branchId = req.student.branchId;
    const subjects = (await fbGet(`content/${branchId}/subjects`)) || {};
    // لا نرجّع كل شجرة الفيديوهات دفعة واحدة إن كانت ضخمة — نرجّع الملخص
    const list = Object.entries(subjects).map(([id, s]) => ({
      id,
      name: s?.name || "",
      image: s?.image || "",
      teachersCount: s?.teachers ? Object.keys(s.teachers).length : 0,
    }));
    res.json({ success: true, branchId, subjects: list });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.get("/api/content/subjects/:subjectId/teachers", requireStudent, async (req, res) => {
  try {
    const base = `content/${req.student.branchId}/subjects/${req.params.subjectId}`;
    const subject = await fbGet(base);
    if (!subject) return jsonError(res, 404, "المادة غير موجودة");
    const teachers = Object.entries(subject.teachers || {}).map(([id, t]) => ({
      id,
      name: t?.name || "",
      image: t?.image || "",
      monthsCount: t?.months ? Object.keys(t.months).length : 0,
    }));
    res.json({ success: true, subject: { id: req.params.subjectId, name: subject.name }, teachers });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.get("/api/content/subjects/:subjectId/teachers/:teacherId/months", requireStudent, async (req, res) => {
  try {
    const base = `content/${req.student.branchId}/subjects/${req.params.subjectId}/teachers/${req.params.teacherId}`;
    const teacher = await fbGet(base);
    if (!teacher) return jsonError(res, 404, "المدرس غير موجود");
    const months = Object.entries(teacher.months || {}).map(([id, m]) => ({
      id,
      name: m?.name || "",
      image: m?.image || "",
      lecturesCount: m?.lectures ? Object.keys(m.lectures).length : 0,
    }));
    res.json({ success: true, teacher: { id: req.params.teacherId, name: teacher.name }, months });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.get(
  "/api/content/subjects/:subjectId/teachers/:teacherId/months/:monthId/lectures",
  requireStudent,
  async (req, res) => {
    try {
      const base = `content/${req.student.branchId}/subjects/${req.params.subjectId}/teachers/${req.params.teacherId}/months/${req.params.monthId}`;
      const month = await fbGet(base);
      if (!month) return jsonError(res, 404, "الشهر غير موجود");
      const lectures = Object.entries(month.lectures || {}).map(([id, l]) => ({
        id,
        name: l?.name || "",
        image: l?.image || "",
        videosCount: l?.videos ? Object.keys(l.videos).length : 0,
      }));
      res.json({ success: true, month: { id: req.params.monthId, name: month.name }, lectures });
    } catch (e) {
      return jsonError(res, 500, e.message);
    }
  }
);

// قائمة فيديوهات محاضرة + روابط embed جاهزة
app.get(
  "/api/content/subjects/:subjectId/teachers/:teacherId/months/:monthId/lectures/:lectureId/videos",
  requireStudent,
  async (req, res) => {
    try {
      const base = `content/${req.student.branchId}/subjects/${req.params.subjectId}/teachers/${req.params.teacherId}/months/${req.params.monthId}/lectures/${req.params.lectureId}`;
      const lecture = await fbGet(base);
      if (!lecture) return jsonError(res, 404, "المحاضرة غير موجودة");
      const videos = Object.entries(lecture.videos || {}).map(([id, v]) => ({
        id,
        name: v?.name || "فيديو",
        duration: v?.duration || "",
        image: v?.image || "",
        // رابط التشغيل للطالب (Bunny public embed)
        embedUrl: bunnyEmbedUrl(v?.url || v?.videoId || ""),
        url: bunnyEmbedUrl(v?.url || v?.videoId || ""),
      }));
      const files = Object.entries(lecture.files || {}).map(([id, f]) => ({
        id,
        name: f?.name || "ملف",
        url: f?.url || "",
        fileType: f?.fileType || "pdf",
      }));
      res.json({
        success: true,
        lecture: { id: req.params.lectureId, name: lecture.name || "محاضرة" },
        videos,
        files,
      });
    } catch (e) {
      return jsonError(res, 500, e.message);
    }
  }
);

// ---------- أدمن: تسجيل دخول بيوزر + باسورد ----------
app.post("/api/admin/login", async (req, res) => {
  try {
    const username = String(req.body?.username || req.body?.email || "")
      .trim()
      .toLowerCase();
    const password = String(req.body?.password || "");

    if (!ADMIN_PASSWORD) {
      return jsonError(res, 500, "ADMIN_PASSWORD غير مضبوط على السيرفر");
    }

    // يقبل: اسم المستخدم (ADMIN_USERNAME) أو إيميل من ADMIN_EMAILS
    const userOk =
      (username && username === ADMIN_USERNAME) ||
      (username && ADMIN_EMAILS.includes(username));

    if (!userOk) {
      return jsonError(res, 403, "اسم المستخدم غير صحيح");
    }
    if (password !== ADMIN_PASSWORD) {
      return jsonError(res, 401, "كلمة المرور غير صحيحة");
    }

    const token = signJwt({ role: "admin", username }, 60 * 60 * 12);
    res.json({ success: true, token, username });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

// ---------- أدمن: إدارة الأكواد ----------
app.get("/api/admin/codes", requireAdmin, async (req, res) => {
  try {
    // تحذير: قراءة الجذر كله ثقيلة لو الأكواد كثيرة — الأفضل مسار codes/
    const root = (await fbGet("/")) || {};
    const codes = [];
    for (const [key, val] of Object.entries(root)) {
      if (!/^\d{9}$/.test(key)) continue;
      if (!val || typeof val !== "object") continue;
      codes.push({
        code: key,
        name: val.studentName || val.name || "",
        branchId: val.branchId || val.section || val.branch || "",
        active: val.active !== false,
        expiresAt: resolveExpiry(val) || null,
        durationType: val.durationType || val.type || val.plan || null,
        lastLoginAt: val.lastLoginAt || null,
      });
    }
    codes.sort((a, b) => String(a.code).localeCompare(String(b.code)));
    res.json({ success: true, codes });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.post("/api/admin/codes", requireAdmin, async (req, res) => {
  try {
    if (!hasAdmin) return jsonError(res, 500, "الكتابة تحتاج Service Account على السيرفر");
    let code = normCode(req.body?.code);
    if (!code) {
      // توليد كود عشوائي 9 أرقام
      do {
        code = String(Math.floor(100000000 + Math.random() * 900000000));
      } while (await fbGet(code));
    }
    if (!/^\d{9}$/.test(code)) return jsonError(res, 400, "الكود يجب أن يكون 9 أرقام");

    const exists = await fbGet(code);
    if (exists) return jsonError(res, 409, "الكود موجود مسبقًا");

    const name = String(req.body?.name || "").trim();
    const branchId = normalizeBranch(req.body?.branchId || req.body?.branch || "");
    if (!branchId) return jsonError(res, 400, "حدد الشعبة");

    const durationType = String(req.body?.durationType || req.body?.type || "month").trim();
    let expiresAt = expiryMs(req.body?.expiresAt);
    if (!expiresAt && durationType) {
      const days = Number(req.body?.days || 30);
      expiresAt = Date.now() + days * 86400000;
    }

    const record = {
      name,
      studentName: name,
      branchId,
      active: true,
      durationType,
      expiresAt,
      maxDevices: Number(req.body?.maxDevices || 2),
      createdAt: Date.now(),
      createdBy: req.admin.email || "admin",
    };

    await fbSet(code, record);
    res.json({ success: true, code, student: record });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.patch("/api/admin/codes/:code", requireAdmin, async (req, res) => {
  try {
    if (!hasAdmin) return jsonError(res, 500, "الكتابة تحتاج Service Account");
    const code = normCode(req.params.code);
    const cur = await fbGet(code);
    if (!cur) return jsonError(res, 404, "الكود غير موجود");

    const patch = {};
    if (req.body.name != null) {
      patch.name = String(req.body.name).trim();
      patch.studentName = patch.name;
    }
    if (req.body.branchId != null || req.body.branch != null) {
      patch.branchId = normalizeBranch(req.body.branchId || req.body.branch);
    }
    if (req.body.active != null) patch.active = Boolean(req.body.active);
    if (req.body.durationType != null) patch.durationType = String(req.body.durationType);
    if (req.body.expiresAt != null) patch.expiresAt = expiryMs(req.body.expiresAt);
    if (req.body.maxDevices != null) patch.maxDevices = Number(req.body.maxDevices);
    if (req.body.days != null) patch.expiresAt = Date.now() + Number(req.body.days) * 86400000;

    await fbUpdate(code, patch);
    res.json({ success: true, code, patch });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/codes/:code", requireAdmin, async (req, res) => {
  try {
    if (!hasAdmin) return jsonError(res, 500, "الحذف يحتاج Service Account");
    const code = normCode(req.params.code);
    await fbRemove(code);
    res.json({ success: true, deleted: code });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

// ---------- أدمن: محتوى ----------
app.get("/api/admin/content/:branchId/subjects", requireAdmin, async (req, res) => {
  try {
    const data = (await fbGet(`content/${req.params.branchId}/subjects`)) || {};
    res.json({ success: true, subjects: data });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.post("/api/admin/content/item", requireAdmin, async (req, res) => {
  try {
    if (!hasAdmin) return jsonError(res, 500, "الكتابة تحتاج Service Account");
    const { branchId, type, name, parentSubjectId, parentTeacherId, parentMonthId, parentLectureId, url, duration, image, fileUrl } = req.body || {};
    const b = normalizeBranch(branchId);
    if (!b || !name || !type) return jsonError(res, 400, "branchId و type و name مطلوبين");

    const id = makeId();
    let pathStr = `content/${b}/subjects`;
    const item = { name: String(name).trim(), createdAt: Date.now() };
    if (image) item.image = String(image).trim();

    if (type === "subject") {
      pathStr += `/${id}`;
    } else if (type === "teacher") {
      if (!parentSubjectId) return jsonError(res, 400, "parentSubjectId مطلوب");
      pathStr += `/${parentSubjectId}/teachers/${id}`;
    } else if (type === "month") {
      if (!parentSubjectId || !parentTeacherId) return jsonError(res, 400, "المادة والمدرس مطلوبين");
      pathStr += `/${parentSubjectId}/teachers/${parentTeacherId}/months/${id}`;
    } else if (type === "lecture") {
      if (!parentSubjectId || !parentTeacherId || !parentMonthId) return jsonError(res, 400, "المسار غير مكتمل");
      pathStr += `/${parentSubjectId}/teachers/${parentTeacherId}/months/${parentMonthId}/lectures/${id}`;
    } else if (type === "video") {
      if (!parentSubjectId || !parentTeacherId || !parentMonthId || !parentLectureId) {
        return jsonError(res, 400, "مسار المحاضرة مطلوب");
      }
      const rawUrl = String(url || "").trim();
      if (!rawUrl) return jsonError(res, 400, "رابط/معرف الفيديو مطلوب");
      item.url = bunnyEmbedUrl(rawUrl);
      item.duration = String(duration || "").trim();
      item.icon = "video";
      pathStr += `/${parentSubjectId}/teachers/${parentTeacherId}/months/${parentMonthId}/lectures/${parentLectureId}/videos/${id}`;
    } else if (type === "pdf") {
      if (!parentSubjectId || !parentTeacherId || !parentMonthId || !parentLectureId) {
        return jsonError(res, 400, "مسار المحاضرة مطلوب");
      }
      item.url = String(fileUrl || url || "").trim();
      item.fileType = "pdf";
      if (!item.url) return jsonError(res, 400, "رابط PDF مطلوب");
      pathStr += `/${parentSubjectId}/teachers/${parentTeacherId}/months/${parentMonthId}/lectures/${parentLectureId}/files/${id}`;
    } else {
      return jsonError(res, 400, "type غير معروف");
    }

    await fbSet(pathStr, item);
    res.json({ success: true, id, path: pathStr, item });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

app.delete("/api/admin/content", requireAdmin, async (req, res) => {
  try {
    if (!hasAdmin) return jsonError(res, 500, "الحذف يحتاج Service Account");
    const pathStr = String(req.body?.path || "").replace(/^\/+/, "");
    if (!pathStr.startsWith("content/")) return jsonError(res, 400, "مسار غير مسموح");
    await fbRemove(pathStr);
    res.json({ success: true, deleted: pathStr });
  } catch (e) {
    return jsonError(res, 500, e.message);
  }
});

// ---------- تشغيل ----------
app.listen(PORT, () => {
  console.log(`[dorosak] listening on :${PORT}`);
  console.log(`[dorosak] firebaseAdmin=${hasAdmin} db=${FIREBASE_DB_URL}`);
  console.log(`[dorosak] bunny library=${BUNNY_LIBRARY_ID} (public embeds)`);
});

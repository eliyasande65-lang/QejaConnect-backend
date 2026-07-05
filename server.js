require("dotenv").config();

const express     = require("express");
const mysql       = require("mysql2");
const cors        = require("cors");
const bcrypt      = require("bcrypt");
const jwt         = require("jsonwebtoken");
const multer      = require("multer");
const streamifier = require("streamifier");
const cloudinary  = require("cloudinary").v2;
const axios       = require("axios");
const webpush     = require("web-push");
const helmet      = require("helmet");
const rateLimit   = require("express-rate-limit");
const { z }       = require("zod");

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require("@simplewebauthn/server");

const SALT_ROUNDS = 12;

const router = express.Router();
const app    = express();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

webpush.setVapidDetails(
  process.env.VAPID_SUBJECT,
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

// =========================
// MIDDLEWARE
// =========================
app.use(helmet());

const allowedOrigins = ["https://eliyasande65-lang.github.io"];

app.use(
  cors({
    origin: (origin, callback) => {
      console.log("Incoming request origin:", origin);
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS: " + origin));
      }
    },
    credentials: true,
  })
);

app.use(express.json());

const loginLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             5,
  message:         { success: false, message: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders:   false,
});

const signupLimiter = rateLimit({
  windowMs:        60 * 60 * 1000,
  max:             5,
  message:         { success: false, message: "Too many sign-ups from this IP. Try again later." },
  standardHeaders: true,
  legacyHeaders:   false,
});

const generalLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             100,
  standardHeaders: true,
  legacyHeaders:   false,
});

app.use(generalLimiter);

// =========================
// VALIDATION SCHEMAS
// =========================
const loginSchema = z.object({
  email:    z.string().email("Invalid email"),
  password: z.string().min(6, "Password too short").max(100),
});

const signupSchema = z.object({
  fullname:      z.string().min(2).max(80),
  email:         z.string().email("Invalid email"),
  phone:         z.string().min(9).max(15),
  password:      z.string().min(6).max(100),
  referral_code: z.string().max(20).optional(),
});

const messageSchema = z.object({
  message: z.string().min(1).max(2000),
});

const sendMessageSchema = z.object({
  conversation_id: z.coerce.number().int().positive(),
  landlord_id:     z.coerce.number().int().positive(),
  tenant_id:       z.coerce.number().int().positive(),
  sender_role:     z.enum(["landlord", "tenant"]),
  message:         z.string().min(1).max(2000),
});

const interestedSchema = z.object({
  landlord_id: z.coerce.number().int().positive(),
  tenant_id:   z.coerce.number().int().positive(),
  message:     z.string().min(1).max(1000),
});

const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({
      success: false,
      message: result.error.issues[0].message,
    });
  }
  req.body = result.data;
  next();
};

// =========================
// DB POOL
// =========================
const db = mysql.createPool({
  host:               process.env.DB_HOST,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  database:           process.env.DB_NAME,
  port:               process.env.DB_PORT,
  ssl:                { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
});

const dbPromise = db.promise();

db.getConnection((err, connection) => {
  if (err) console.log("DB Error:", err.message);
  else {
    console.log("MySQL Pool Connected ✅");
    connection.release();
  }
});

// =========================
// MULTER
// =========================
const storage = multer.memoryStorage();
const upload  = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// =========================
// AUTH MIDDLEWARE
// =========================
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });
  const token = header.split(" ")[1];
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// =========================
// ADMIN MIDDLEWARE
// =========================
function adminAuth(req, res, next) {
  const secret = req.headers["x-admin-secret"];
  if (!secret || secret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }
  next();
}

let subscriptions = [];

// =========================
// ACTIVITY LOGGING & PRESENCE HELPERS
// =========================

// Records a single action in the activity feed.
// action examples: "login", "signup", "messaged_landlord", "booked_property",
// "sent_message", "uploaded_property", "renewed_listing", "paid_rent",
// "requested_extension", "updated_profile_pic"
async function logActivity(userId, role, action, details = null, req = null) {
  try {
    const ip = req ? (req.headers["x-forwarded-for"] || req.socket.remoteAddress) : null;
    const ua = req ? req.headers["user-agent"] : null;
    await dbPromise.query(
      `INSERT INTO activity_logs (user_id, role, action, details, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [userId, role, action, details ? JSON.stringify(details) : null, ip, ua]
    );
  } catch (err) {
    console.error("[ACTIVITY LOG]", err.message);
  }
}

// Marks a user as "seen right now" — called on login and on every heartbeat ping.
async function touchPresence(userId, role, req) {
  try {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const ua = req.headers["user-agent"];
    await dbPromise.query(
      `INSERT INTO user_presence (user_id, role, last_seen_at, login_at, ip_address, user_agent)
       VALUES (?, ?, NOW(), NOW(), ?, ?)
       ON DUPLICATE KEY UPDATE
         last_seen_at = NOW(),
         ip_address   = VALUES(ip_address),
         user_agent   = VALUES(user_agent)`,
      [userId, role, ip, ua]
    );
  } catch (err) {
    console.error("[PRESENCE]", err.message);
  }
}

// =========================
// ROOT
// =========================
app.get("/", (req, res) => {
  res.json({ message: "QejaConnect API running 🚀" });
});

// =========================
// SIGNUP
// =========================
app.post("/signup", signupLimiter, validate(signupSchema), async (req, res) => {
  const { fullname, email, phone, password, referral_code } = req.body;

  if (!/^(\+254|0)[71]\d{8}$/.test(phone)) {
    return res.status(400).json({ success: false, message: "Invalid phone number format" });
  }

  try {
    let referredBy = null;

    if (referral_code && referral_code.trim()) {
      const [refRows] = await dbPromise.query(
        `SELECT id, referral_code FROM users WHERE referral_code = ?`,
        [referral_code.trim().toUpperCase()]
      );
      if (refRows.length) referredBy = refRows[0].referral_code;
    }

    const hashed    = await bcrypt.hash(password, SALT_ROUNDS);
    const displayId = await getNextDisplayId("users", "QT");

    const [result] = await dbPromise.query(
      `INSERT INTO users (fullname, email, phone, password, referred_by, display_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [fullname, email, phone, hashed, referredBy, displayId]
    );

    const myCode = `REF${1000 + result.insertId}`;
    await dbPromise.query(
      `UPDATE users SET referral_code = ? WHERE id = ?`,
      [myCode, result.insertId]
    );

    res.json({ success: true, message: "User created", tenant_id: displayId });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ success: false, message: "Email already registered" });
    }
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// LOGIN
// =========================
app.post("/login", loginLimiter, validate(loginSchema), async (req, res) => {
  const { email, password } = req.body;

  try {
    const [users] = await dbPromise.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (users.length > 0) {
      const user  = users[0];
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ success: false, message: "Wrong password" });
      }
      const token = jwt.sign(
        { id: user.id, role: "tenant" },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );
      const { password: _pw, ...safeUser } = user;
      await touchPresence(user.id, "tenant", req);
      await logActivity(user.id, "tenant", "login", null, req);
      return res.json({ success: true, role: "tenant", token, user: safeUser });
    }

    const [landlords] = await dbPromise.query(
      "SELECT * FROM landlords WHERE email = ?",
      [email]
    );

    if (landlords.length === 0) {
      return res.status(401).json({ success: false, message: "User not found" });
    }

    const landlord = landlords[0];
    const valid    = await bcrypt.compare(password, landlord.password);
    if (!valid) {
      return res.status(401).json({ success: false, message: "Wrong password" });
    }

    const token = jwt.sign(
      { id: landlord.id, role: "landlord" },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    const { password: _pw, ...safeLandlord } = landlord;
    await touchPresence(landlord.id, "landlord", req);
    await logActivity(landlord.id, "landlord", "login", null, req);
    res.json({ success: true, role: "landlord", token, user: safeLandlord });
  } catch (err) {
    console.error("[LOGIN ERROR]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// ACTIVITY HEARTBEAT
// =========================
app.post("/activity/heartbeat", auth, async (req, res) => {
  await touchPresence(req.user.id, req.user.role, req);
  res.json({ success: true });
});

// =========================
// REFERRALS
// =========================
router.get("/referrals/:id", auth, async (req, res) => {
  try {
    const [userRows] = await dbPromise.query(
      `SELECT referral_code FROM users WHERE id = ?`,
      [req.params.id]
    );
    if (!userRows.length) return res.json({ success: false, message: "User not found" });

    const referral_code = userRows[0].referral_code;

    const [earnings] = await dbPromise.query(
      `SELECT re.id, re.rent_amount, re.reward_amount, re.status, re.paid_at, re.created_at,
              u.fullname AS referred_name
       FROM referral_earnings re
       JOIN users u ON re.referred_id = u.id
       WHERE re.referrer_id = ?
       ORDER BY re.created_at DESC`,
      [req.params.id]
    );

    const totalEarned  = earnings.reduce((sum, e) => sum + parseFloat(e.reward_amount), 0);
    const totalPaid    = earnings
      .filter((e) => e.status === "paid")
      .reduce((sum, e) => sum + parseFloat(e.reward_amount), 0);
    const totalPending = totalEarned - totalPaid;

    res.json({ success: true, referral_code, totalEarned, totalPaid, totalPending, earnings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// ADMIN: LIST / SEARCH TENANTS
// =========================
router.get("/admin/tenants", adminAuth, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(100, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const search = (req.query.search || "").trim();

    let where  = "";
    let params = [];

    if (search) {
      where  = `WHERE fullname LIKE ? OR email LIKE ? OR phone LIKE ? OR display_id LIKE ?`;
      params = [`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`];
    }

    const [countRows] = await dbPromise.query(
      `SELECT COUNT(*) AS total FROM users ${where}`,
      params
    );
    const total = countRows[0].total;

    const [rows] = await dbPromise.query(
      `SELECT id, display_id, fullname, email, phone, profile_pic, created_at
       FROM users ${where}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({ success: true, total, page, limit, tenants: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// ADMIN: EMAIL A TENANT
// =========================
const { Resend } = require("resend");
const resend = new Resend(process.env.RESEND_API_KEY);

router.post("/admin/tenants/:id/email", adminAuth, async (req, res) => {
  try {
    const { subject, message } = req.body;
    if (!subject || !message) {
      return res.status(400).json({ success: false, message: "Subject and message required" });
    }

    const [rows] = await dbPromise.query(
      `SELECT email, fullname FROM users WHERE id = ?`,
      [req.params.id]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: "Tenant not found" });
    }

    await resend.emails.send({
      from:    "QejaConnect <onboarding@resend.dev>",
      to:      rows[0].email,
      subject,
      text:    message,
    });

    res.json({ success: true, message: `Email sent to ${rows[0].fullname}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Failed to send email" });
  }
});

// =========================
// PUSH NOTIFICATIONS
// =========================
app.post("/subscribe", (req, res) => {
  subscriptions.push(req.body);
  res.status(201).json({ success: true, message: "Subscribed" });
});

app.post("/send-push", auth, async (req, res) => {
  const payload = JSON.stringify({
    title: "🏠 New Property Added",
    body:  "Check out the latest listing on QejaConnect!",
    url:   "/QejaConnect/welcome.html",
  });
  try {
    await Promise.all(subscriptions.map((sub) => webpush.sendNotification(sub, payload)));
    res.json({ success: true, message: "Notifications sent" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// GET ALL PROPERTIES
// =========================
app.get("/properties", (req, res) => {
  const sql = `
    SELECT p.*, l.fullname AS landlord_name
    FROM properties p
    LEFT JOIN landlords l ON p.landlord_id = l.id
    WHERE l.verified = 1
      AND (p.listing_expires_at IS NULL OR p.listing_expires_at > NOW())
    ORDER BY p.id DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, properties: results });
  });
});

//renew 
// =========================
// RENEW PROPERTY LISTING (PAID — KSh 95 per unit)
// ─ Renewal now requires proof of M-Pesa payment before the listing
//   is reactivated. The client sends the mpesa_transaction_id from a
//   completed /mpesa/stk-push flow; we verify it belongs to this
//   landlord and is 'completed' in mpesa_payments (same pattern used
//   by /upload-property), then extend listing_expires_at by 30 days
//   and mark the payment as 'used' so it can't be replayed.
// =========================
app.patch("/renew-property/:id", auth, async (req, res) => {
  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Only landlords can renew listings." });
  }

  const { mpesa_transaction_id } = req.body;
  if (!mpesa_transaction_id) {
    return res.status(400).json({
      success: false,
      message: "Payment verification required. Please complete M-Pesa payment first.",
    });
  }

  try {
    const [rows] = await dbPromise.query(
      `SELECT id, landlord_id FROM properties WHERE id = ?`,
      [req.params.id]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: "Property not found." });
    }
    if (rows[0].landlord_id !== req.user.id) {
      return res.status(403).json({ success: false, message: "Not your property." });
    }

    const [payRows] = await dbPromise.query(
      `SELECT id FROM mpesa_payments
       WHERE transaction_id=? AND landlord_id=? AND status='completed' LIMIT 1`,
      [mpesa_transaction_id, req.user.id]
    );
    if (payRows.length === 0) {
      return res.status(402).json({
        success: false,
        message: "Payment not verified. Please complete M-Pesa payment first.",
      });
    }

    const newExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await dbPromise.query(
      `UPDATE properties SET listing_expires_at = ? WHERE id = ?`,
      [newExpiry, req.params.id]
    );

    await dbPromise.query(
      `UPDATE mpesa_payments SET status='used' WHERE transaction_id=?`,
      [mpesa_transaction_id]
    );
    await logActivity(req.user.id, "landlord", "renewed_listing", { property_id: req.params.id }, req);
    res.json({ success: true, message: "Listing renewed", listing_expires_at: newExpiry });
  } catch (err) {
    console.error("[RENEW PROPERTY]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// GET PROPERTIES BY LANDLORD ID
// =========================
app.get("/landlord-properties/:id", auth, (req, res) => {
  const sql = `
    SELECT id, title, price, location, type, units, listing_expires_at, created_at
    FROM properties
    WHERE landlord_id = ?
    ORDER BY id DESC
  `;
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, properties: results });
  });
});

// =========================
// GET ALL LANDLORDS (public)
// =========================
app.get("/landlords", (req, res) => {
  const sql = `
    SELECT id, fullname, email, town, county, profile_pic, property_name
    FROM landlords
    WHERE verified = 1
    ORDER BY id DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, landlords: results });
  });
});

// =========================
// GET SINGLE LANDLORD (public)
// =========================
app.get("/landlords/:id", (req, res) => {
  const sql = `
    SELECT id, fullname, email, phone, town, county,
           profile_pic, property_name, property_type, units, description
    FROM landlords
    WHERE id = ? AND verified = 1
  `;
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Landlord not found" });
    }
    res.json({ success: true, landlord: results[0] });
  });
});

// =========================
// INTERESTED -> START CHAT
// =========================
app.post("/interested", auth, validate(interestedSchema), async (req, res) => {
  const { landlord_id, tenant_id, message } = req.body;

  try {
    const [landlordRows] = await dbPromise.query(
      `SELECT fullname FROM landlords WHERE id = ?`,
      [landlord_id]
    );
    const landlord_name = landlordRows[0]?.fullname || "Landlord";

    const [existing] = await dbPromise.query(
      `SELECT * FROM conversations WHERE landlord_id = ? AND tenant_id = ?`,
      [landlord_id, tenant_id]
    );

    if (existing.length > 0) {
      const conversation_id = existing[0].id;
      await dbPromise.query(
        `INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
         VALUES (?, ?, ?, 'tenant', ?)`,
        [conversation_id, landlord_id, tenant_id, message]
      );
      await logActivity(tenant_id, "tenant", "messaged_landlord", { landlord_id, landlord_name }, req);
      return res.json({ success: true, message: "Chat started", conversation_id, landlord_name });
    }

    const [result] = await dbPromise.query(
      `INSERT INTO conversations (landlord_id, tenant_id) VALUES (?, ?)`,
      [landlord_id, tenant_id]
    );
    const conversation_id = result.insertId;
    await dbPromise.query(
      `INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
       VALUES (?, ?, ?, 'tenant', ?)`,
      [conversation_id, landlord_id, tenant_id, message]
    );
    await logActivity(tenant_id, "tenant", "messaged_landlord", { landlord_id, landlord_name }, req);
    return res.json({ success: true, message: "Chat started", conversation_id, landlord_name });
  } catch (err) {
    console.error("[INTERESTED]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// LANDLORD CHATS
// =========================
app.get("/landlord-chats/:id", auth, (req, res) => {
  const sql = `
    SELECT
      conversations.id AS conversation_id,
      users.id AS tenant_id,
      users.fullname,
      users.email,
      (SELECT message FROM chats
       WHERE conversation_id = conversations.id
       ORDER BY id DESC LIMIT 1) AS last_message
    FROM conversations
    JOIN users ON conversations.tenant_id = users.id
    WHERE conversations.landlord_id = ?
    ORDER BY conversations.id DESC
  `;
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, chats: results });
  });
});

// =========================
// TENANT CHATS
// =========================
app.get("/tenant-chats/:id", auth, (req, res) => {
  const sql = `
    SELECT
      conversations.id AS conversation_id,
      landlords.id AS landlord_id,
      landlords.fullname,
      landlords.email,
      (SELECT message FROM chats
       WHERE conversation_id = conversations.id
       ORDER BY id DESC LIMIT 1) AS last_message
    FROM conversations
    JOIN landlords ON conversations.landlord_id = landlords.id
    WHERE conversations.tenant_id = ?
    ORDER BY conversations.id DESC
  `;
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, chats: results });
  });
});

// =========================
// SEND MESSAGE
// =========================
app.post("/send-message", auth, validate(sendMessageSchema), (req, res) => {
  const { conversation_id, landlord_id, tenant_id, sender_role, message } = req.body;

  const checkSql = `
    SELECT * FROM conversations
    WHERE id = ? AND (landlord_id = ? OR tenant_id = ?)
  `;
  db.query(checkSql, [conversation_id, req.user.id, req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    if (rows.length === 0) {
      return res.status(403).json({ success: false, message: "Not your conversation" });
    }

    db.query(
      `INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
       VALUES (?, ?, ?, ?, ?)`,
      [conversation_id, landlord_id, tenant_id, sender_role, message],
      // FIX: this callback must be async since it awaits logActivity below.
      async (err2) => {
        if (err2) return res.status(500).json({ success: false, message: "Server error" });
        await logActivity(req.user.id, req.user.role, "sent_message", { conversation_id }, req);
        res.json({ success: true, message: "Message sent" });
      }
    );
  });
});

// =========================
// CONTACT MESSAGE
// =========================
app.post("/contact", auth, validate(messageSchema), (req, res) => {
  const { message }   = req.body;
  const sender_id     = req.user.id;
  const sender_role   = req.user.role;

  db.query(
    `INSERT INTO contact_messages (sender_id, sender_role, message) VALUES (?, ?, ?)`,
    [sender_id, sender_role, message],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      res.json({ success: true, message: "Message sent to support" });
    }
  );
});

// =========================
// GET MESSAGES IN A CONVERSATION
// =========================
app.get("/messages/:conversation_id", auth, (req, res) => {
  const conversation_id = req.params.conversation_id;
  const user_id         = req.user.id;

  db.query(
    `SELECT * FROM conversations WHERE id = ? AND (landlord_id = ? OR tenant_id = ?)`,
    [conversation_id, user_id, user_id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      if (result.length === 0) {
        return res.status(403).json({ success: false, message: "Not allowed to access this chat" });
      }

      db.query(
        `SELECT * FROM chats WHERE conversation_id = ? ORDER BY id ASC`,
        [conversation_id],
        (err2, messages) => {
          if (err2) return res.status(500).json({ success: false, message: "Server error" });
          const conv = result[0];
          res.json({
            success: true,
            messages,
            landlord_id: conv.landlord_id,
            tenant_id:   conv.tenant_id,
          });
        }
      );
    }
  );
});

// =========================
// UPLOAD LANDLORD PROFILE PIC
// =========================
app.post("/upload-profile-pic", auth, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No image uploaded" });
  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Landlords only" });
  }

  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: "qejaconnect_profiles" },
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "Upload failed" });
      db.query(
        `UPDATE landlords SET profile_pic = ? WHERE id = ?`,
        [result.secure_url, req.user.id],
        (err2) => {
          if (err2) return res.status(500).json({ success: false, message: "Server error" });
          res.json({ success: true, image: result.secure_url });
        }
      );
    }
  );
  streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
});

// =========================
// DISPLAY ID GENERATOR
// =========================
async function getNextDisplayId(table, prefix) {
  const [rows] = await dbPromise.query(
    `SELECT display_id FROM ${table}
     WHERE display_id IS NOT NULL
     ORDER BY id DESC LIMIT 1`
  );

  let nextNum = 1;
  if (rows.length && rows[0].display_id) {
    const match = rows[0].display_id.match(/\d+$/);
    if (match) nextNum = parseInt(match[0], 10) + 1;
  }
  return `${prefix}${String(nextNum).padStart(3, "0")}`;
}

// =========================
// REGISTER LANDLORD
// =========================
app.post(
  "/register-landlord",
  signupLimiter,
  upload.fields([
    { name: "profile_pic", maxCount: 1 },
    { name: "id_photo",    maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        fullname, email, phone, id, kra, county,
        town, property, type, units, description, password,
      } = req.body;

      const profileFile = req.files?.["profile_pic"]?.[0];
      const idFile      = req.files?.["id_photo"]?.[0];

      if (!profileFile) return res.status(400).json({ success: false, message: "Profile image required" });
      if (!idFile)      return res.status(400).json({ success: false, message: "National ID photo required" });
      if (!fullname || !email || !password) {
        return res.status(400).json({ success: false, message: "fullname, email and password are required" });
      }

      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const displayId      = await getNextDisplayId("landlords", "QL");

      function uploadToCloudinary(buffer, folder) {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream({ folder }, (err, result) => {
            if (err) return reject(err);
            resolve(result.secure_url);
          });
          streamifier.createReadStream(buffer).pipe(stream);
        });
      }

      const [profile_pic_url, id_photo_url] = await Promise.all([
        uploadToCloudinary(profileFile.buffer, "qejaconnect_profiles"),
        uploadToCloudinary(idFile.buffer,      "qejaconnect_ids"),
      ]);

      const sql = `
        INSERT INTO landlords
          (fullname, email, phone, national_id, kra_pin, county, town,
           property_name, property_type, units, description,
           profile_pic, id_photo, password, verified, display_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
      `;

      db.query(
        sql,
        [
          fullname, email, phone, id, kra, county, town,
          property, type, units, description,
          profile_pic_url, id_photo_url, hashedPassword, displayId,
        ],
        (err2) => {
          if (err2) {
            if (err2.code === "ER_DUP_ENTRY") {
              return res.status(409).json({ success: false, message: "Email already registered" });
            }
            return res.status(500).json({ success: false, message: "Server error" });
          }
          res.json({ success: true, message: "Landlord registered", landlord_id: displayId });
        }
      );
    } catch (err) {
      console.error("[REGISTER LANDLORD]", err.message);
      res.status(500).json({ success: false, message: "Server error" });
    }
  }
);

// =========================
// ADMIN: ONLINE USERS / PRESENCE / ACTIVITY LOGS
// =========================

// Who is online RIGHT NOW (seen in the last 2 minutes)
router.get("/admin/online-users", adminAuth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT up.user_id, up.role, up.last_seen_at, up.login_at, up.ip_address,
              CASE WHEN up.role='tenant'   THEN u.fullname
                   WHEN up.role='landlord' THEN l.fullname END AS fullname,
              CASE WHEN up.role='tenant'   THEN u.email
                   WHEN up.role='landlord' THEN l.email   END AS email
       FROM user_presence up
       LEFT JOIN users     u ON up.role='tenant'   AND up.user_id=u.id
       LEFT JOIN landlords l ON up.role='landlord' AND up.user_id=l.id
       WHERE up.last_seen_at > (NOW() - INTERVAL 2 MINUTE)
       ORDER BY up.last_seen_at DESC`
    );
    res.json({ success: true, online: rows });
  } catch (err) {
    console.error("[ADMIN ONLINE USERS]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Everyone's last-seen time, whether online now or not (for "last active" column)
router.get("/admin/presence", adminAuth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT up.user_id, up.role, up.last_seen_at, up.login_at, up.ip_address,
              CASE WHEN up.role='tenant'   THEN u.fullname
                   WHEN up.role='landlord' THEN l.fullname END AS fullname,
              CASE WHEN up.role='tenant'   THEN u.email
                   WHEN up.role='landlord' THEN l.email   END AS email
       FROM user_presence up
       LEFT JOIN users     u ON up.role='tenant'   AND up.user_id=u.id
       LEFT JOIN landlords l ON up.role='landlord' AND up.user_id=l.id
       ORDER BY up.last_seen_at DESC`
    );
    res.json({ success: true, presence: rows });
  } catch (err) {
    console.error("[ADMIN PRESENCE]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Activity log with filters (user, role, action, date range, name search) + pagination
router.get("/admin/activity-logs", adminAuth, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(100, parseInt(req.query.limit) || 30);
    const offset = (page - 1) * limit;

    const where  = [];
    const params = [];

    if (req.query.user_id) { where.push("al.user_id = ?");     params.push(req.query.user_id); }
    if (req.query.role)    { where.push("al.role = ?");        params.push(req.query.role); }
    if (req.query.action)  { where.push("al.action = ?");      params.push(req.query.action); }
    if (req.query.from)    { where.push("al.created_at >= ?"); params.push(req.query.from); }
    if (req.query.to)      { where.push("al.created_at <= ?"); params.push(req.query.to); }
    if (req.query.search) {
      where.push("(u.fullname LIKE ? OR l.fullname LIKE ?)");
      params.push(`%${req.query.search}%`, `%${req.query.search}%`);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [countRows] = await dbPromise.query(
      `SELECT COUNT(*) AS total
       FROM activity_logs al
       LEFT JOIN users     u ON al.role='tenant'   AND al.user_id=u.id
       LEFT JOIN landlords l ON al.role='landlord' AND al.user_id=l.id
       ${whereSql}`,
      params
    );

    const [rows] = await dbPromise.query(
      `SELECT al.id, al.user_id, al.role, al.action, al.details, al.ip_address, al.created_at,
              CASE WHEN al.role='tenant'   THEN u.fullname
                   WHEN al.role='landlord' THEN l.fullname END AS fullname
       FROM activity_logs al
       LEFT JOIN users     u ON al.role='tenant'   AND al.user_id=u.id
       LEFT JOIN landlords l ON al.role='landlord' AND al.user_id=l.id
       ${whereSql}
       ORDER BY al.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({ success: true, total: countRows[0].total, page, limit, logs: rows });
  } catch (err) {
    console.error("[ADMIN ACTIVITY LOGS]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// ADMIN: LIST ALL LANDLORDS
// ─ FIX: now respects ?verified= filter so the admin panel can
//   show pending, approved, rejected, or ALL landlords.
//   Also returns every column the admin card needs (profile_pic,
//   id_photo, national_id, kra_pin, county, town, etc.)
//   plus proper pagination via total / limit.
// =========================
app.get("/admin/landlords", adminAuth, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(100, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    // Build WHERE clause based on ?verified= query param
    // Accepted values: 0 (pending), 1 (approved), -1 (rejected)
    // Omit (or pass all=1) to get every landlord regardless of status.
    let where  = "";
    let params = [];

    const verifiedParam = req.query.verified;
    if (verifiedParam !== undefined && verifiedParam !== "") {
      const v = parseInt(verifiedParam, 10);
      if (!isNaN(v) && [-1, 0, 1].includes(v)) {
        where  = "WHERE verified = ?";
        params = [v];
      }
    }

    // Total count (for pagination)
    const [countRows] = await dbPromise.query(
      `SELECT COUNT(*) AS total FROM landlords ${where}`,
      params
    );
    const total = countRows[0].total;

    // Full row for admin cards
    const [landlords] = await dbPromise.query(
      `SELECT id, display_id, fullname, email, phone,
              national_id, kra_pin, county, town,
              property_name, property_type, units, description,
              profile_pic, id_photo, verified, created_at
       FROM landlords
       ${where}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({ success: true, total, page, limit, landlords });
  } catch (err) {
    console.error("[ADMIN LANDLORDS]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// ADMIN: APPROVE / REJECT LANDLORD
// =========================
app.patch("/admin/landlords/:id/verify", adminAuth, (req, res) => {
  const { id }     = req.params;
  const { action } = req.body;

  if (!["approve", "reject"].includes(action)) {
    return res.status(400).json({
      success: false,
      message: 'action must be "approve" or "reject"',
    });
  }

  const verified = action === "approve" ? 1 : -1;

  db.query(
    "UPDATE landlords SET verified = ? WHERE id = ?",
    [verified, id],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      res.json({ success: true, message: `Landlord ${action}d` });
    }
  );
});

// =========================
// ADMIN: LANDLORD RENT OVERVIEW
// (used by admin-landlord.html — separate from the verification list)
// =========================
app.get("/admin/landlords-overview", adminAuth, async (req, res) => {
  try {
    const [landlords] = await dbPromise.query(`
      SELECT id, display_id, fullname, email, phone
      FROM landlords
      WHERE verified = 1
      ORDER BY created_at DESC
    `);

    const enriched = await Promise.all(
      landlords.map(async (ll) => {
        const [tenancies] = await dbPromise.query(
          `SELECT ten.id, ten.start_date, ten.duration_months, ten.rent_amount,
                  p.title AS property_title,
                  u.fullname AS tenant_name, u.phone AS tenant_phone
           FROM tenancies ten
           JOIN properties p ON ten.property_id = p.id
           JOIN users u      ON ten.tenant_id   = u.id
           WHERE ten.landlord_id = ? AND ten.status = 'active'`,
          [ll.id]
        );

        let paid_count = 0, overdue_count = 0, total_collected = 0;
        const now = new Date();

        for (const t of tenancies) {
          const [payments] = await dbPromise.query(
            `SELECT month_index, month_number, amount, mpesa_ref
             FROM rent_payments WHERE tenancy_id = ? AND status = 'paid'`,
            [t.id]
          );

          t.payments       = payments;
          paid_count      += payments.length;
          total_collected += payments.reduce((s, p) => s + Number(p.amount || 0), 0);

          const start = new Date(t.start_date);
          for (let i = 0; i < (t.duration_months || 12); i++) {
            const due = new Date(start);
            due.setMonth(due.getMonth() + i);
            due.setDate(1);
            if (due <= now) {
              const wasPaid = payments.some(
                (p) => p.month_index === i || p.month_number === i + 1
              );
              if (!wasPaid) overdue_count++;
            }
          }
        }

        return { ...ll, tenancies, paid_count, overdue_count, total_collected };
      })
    );

    res.json({ success: true, landlords: enriched });
  } catch (err) {
    console.error("[ADMIN LANDLORDS OVERVIEW]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// M-PESA
// =========================
async function getMpesaToken() {
  const credentials = Buffer.from(
    `${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`
  ).toString("base64");

  const { data } = await axios.get(
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: `Basic ${credentials}` } }
  );
  return data.access_token;
}

function getMpesaPassword(timestamp) {
  return Buffer.from(
    `${process.env.MPESA_SHORTCODE}${process.env.MPESA_PASSKEY}${timestamp}`
  ).toString("base64");
}

function getTimestamp() {
  return new Date()
    .toLocaleString("en-KE", { timeZone: "Africa/Nairobi" })
    .replace(/[^0-9]/g, "")
    .replace(
      /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/,
      "20$3$2$1$4$5$6"
    );
}

app.post("/mpesa/stk-push", auth, async (req, res) => {
  let { phone, amount, description } = req.body;

  phone = String(phone).replace(/^\+/, "").replace(/^0/, "254");

  if (!/^2547\d{8}$|^2541\d{8}$/.test(phone)) {
    return res.status(400).json({ success: false, message: "Invalid phone number format" });
  }
  if (!amount || isNaN(amount) || amount < 1) {
    return res.status(400).json({ success: false, message: "Invalid amount" });
  }

  try {
    const token     = await getMpesaToken();
    const timestamp = getTimestamp();
    const password  = getMpesaPassword(timestamp);
    const shortcode = process.env.MPESA_SHORTCODE;

    const { data } = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      {
        BusinessShortCode: shortcode,
        Password:          password,
        Timestamp:         timestamp,
        TransactionType:   "CustomerPayBillOnline",
        Amount:            Math.ceil(amount),
        PartyA:            phone,
        PartyB:            shortcode,
        PhoneNumber:       phone,
        CallBackURL:       process.env.MPESA_CALLBACK_URL,
        AccountReference:  "QejaConnect",
        TransactionDesc:   description || "Property listing fee",
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (data.ResponseCode !== "0") {
      return res
        .status(400)
        .json({ success: false, message: data.ResponseDescription || "STK push failed" });
    }

    db.query(
      `INSERT INTO mpesa_payments (checkout_request_id, landlord_id, phone, amount, status, created_at)
       VALUES (?, ?, ?, ?, 'pending', NOW())`,
      [data.CheckoutRequestID, req.user.id, phone, amount],
      (err) => {
        if (err) console.error("DB insert mpesa_payments:", err.message);
      }
    );

    return res.json({
      success:           true,
      CheckoutRequestID: data.CheckoutRequestID,
      message:           "STK push sent successfully",
    });
  } catch (err) {
    console.error("[STK PUSH]", err.response?.data || err.message);
    return res
      .status(500)
      .json({ success: false, message: "Could not initiate M-Pesa payment. Try again." });
  }
});

app.post("/mpesa/callback", (req, res) => {
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });

  try {
    const body    = req.body?.Body?.stkCallback;
    const checkId = body?.CheckoutRequestID;
    const code    = body?.ResultCode;
    if (!checkId) return;

    if (code === 0) {
      const items   = body?.CallbackMetadata?.Item || [];
      const receipt = items.find((i) => i.Name === "MpesaReceiptNumber")?.Value || null;
      const amount  = items.find((i) => i.Name === "Amount")?.Value           || null;
      const phone   = items.find((i) => i.Name === "PhoneNumber")?.Value      || null;

      db.query(
        `UPDATE mpesa_payments
         SET status='completed', transaction_id=?, amount=COALESCE(?,amount),
             phone=COALESCE(?,phone), paid_at=NOW()
         WHERE checkout_request_id=?`,
        [receipt, amount, phone, checkId],
        (err) => {
          if (err) console.error("Callback update (success):", err.message);
        }
      );
    } else {
      db.query(
        `UPDATE mpesa_payments SET status='failed', result_desc=? WHERE checkout_request_id=?`,
        [body?.ResultDesc || "Failed", checkId],
        (err) => {
          if (err) console.error("Callback update (fail):", err.message);
        }
      );
    }
  } catch (err) {
    console.error("Callback parsing error:", err.message);
  }
});

app.post("/mpesa/check-payment", auth, (req, res) => {
  const { checkoutRequestId } = req.body;
  if (!checkoutRequestId) {
    return res.status(400).json({ success: false, message: "checkoutRequestId required" });
  }

  db.query(
    `SELECT status, transaction_id, result_desc FROM mpesa_payments
     WHERE checkout_request_id = ? LIMIT 1`,
    [checkoutRequestId],
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      if (rows.length === 0) return res.json({ success: true, status: "pending" });
      const { status, transaction_id, result_desc } = rows[0];
      res.json({
        success:        true,
        status,
        transaction_id: transaction_id || null,
        message:        result_desc    || null,
      });
    }
  );
});

// =========================
// UPLOAD PROPERTY
// =========================
app.post("/upload-property", auth, upload.single("image"), (req, res) => {
  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Only landlords can list properties." });
  }

  const {
    landlord_id, title, price, location,
    description, type, maps_url,
    mpesa_transaction_id, listing_expires_at,
  } = req.body;

  if (!req.file) return res.status(400).json({ success: false, message: "Image required" });

  if (parseInt(landlord_id) !== req.user.id) {
    return res.status(403).json({ success: false, message: "Forbidden" });
  }

  db.query(
    `SELECT id FROM mpesa_payments
     WHERE transaction_id=? AND landlord_id=? AND status='completed' LIMIT 1`,
    [mpesa_transaction_id, landlord_id],
    (verifyErr, verifyRows) => {
      if (verifyErr) return res.status(500).json({ success: false, message: "Server error" });
      if (verifyRows.length === 0) {
        return res.status(402).json({
          success: false,
          message: "Payment not verified. Please complete M-Pesa payment first.",
        });
      }

      const uploadStream = cloudinary.uploader.upload_stream(
        { folder: "qejaconnect" },
        (err, result) => {
          if (err) return res.status(500).json({ success: false, message: "Upload failed" });

          const expiresAt = listing_expires_at
            ? new Date(listing_expires_at)
            : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

          db.query(
            `INSERT INTO properties
               (landlord_id, title, price, location, description, type,
                image_url, maps_url, listing_expires_at, mpesa_transaction_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              landlord_id, title, price, location, description, type,
              result.secure_url, maps_url || null, expiresAt, mpesa_transaction_id,
            ],
            // FIX: this callback must be async since it awaits logActivity below.
            // Also parseInt(landlord_id) so activity_logs.user_id stores a number,
            // consistent with the other logActivity(...) calls elsewhere in this file.
            async (err2) => {
              if (err2) return res.status(500).json({ success: false, message: "Server error" });
              db.query(
                `UPDATE mpesa_payments SET status='used' WHERE transaction_id=?`,
                [mpesa_transaction_id]
              );
              await logActivity(parseInt(landlord_id), "landlord", "uploaded_property", { title }, req);
              res.json({ success: true, message: "Property uploaded", image_url: result.secure_url });
            }
          );
        }
      );
      streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
    }
  );
});

// =========================
// TENANCY EXTENSION
// =========================
app.get("/landlord/extension-requests/:landlordId", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT er.*, p.title AS property_title, p.location, t.rent_amount, t.duration_months,
              t.start_date, u.fullname AS tenant_name, u.phone AS tenant_phone
       FROM tenancy_extension_requests er
       JOIN tenancies t  ON t.id = er.tenancy_id
       JOIN properties p ON p.id = t.property_id
       JOIN users u      ON u.id = er.tenant_id
       WHERE er.landlord_id = ?
       ORDER BY er.created_at DESC`,
      [req.params.landlordId]
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/tenancy/extension-request", auth, async (req, res) => {
  const { tenancy_id, landlord_id, tenant_id, extra_months, message } = req.body;

  if (!tenancy_id || !landlord_id || !tenant_id || !extra_months || extra_months < 1) {
    return res.status(400).json({ success: false, message: "Missing or invalid fields." });
  }

  try {
    const [result] = await dbPromise.query(
      `INSERT INTO tenancy_extension_requests
       (tenancy_id, landlord_id, tenant_id, extra_months, message)
       VALUES (?, ?, ?, ?, ?)`,
      [tenancy_id, landlord_id, tenant_id, extra_months, message || null]
    );
    await logActivity(tenant_id, "tenant", "requested_extension", { tenancy_id, extra_months }, req);
    res.json({ success: true, request_id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

app.post("/tenancy/extension-request/:id/respond", auth, async (req, res) => {
  const { id }     = req.params;
  const { action } = req.body;

  if (!["approve", "decline"].includes(action)) {
    return res.status(400).json({ success: false, message: "Invalid action." });
  }

  const conn = await dbPromise.getConnection();
  try {
    await conn.beginTransaction();

    const [[reqRow]] = await conn.query(
      `SELECT * FROM tenancy_extension_requests WHERE id = ? AND status = 'pending'`,
      [id]
    );
    if (!reqRow) {
      await conn.rollback();
      conn.release();
      return res
        .status(404)
        .json({ success: false, message: "Request not found or already handled." });
    }

    if (action === "approve") {
      await conn.query(
        `UPDATE tenancies SET duration_months = duration_months + ? WHERE id = ?`,
        [reqRow.extra_months, reqRow.tenancy_id]
      );
    }

    await conn.query(
      `UPDATE tenancy_extension_requests
       SET status = ?, responded_at = NOW() WHERE id = ?`,
      [action === "approve" ? "approved" : "declined", id]
    );

    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    console.error(err);
    res.status(500).json({ success: false, message: "Server error." });
  } finally {
    conn.release();
  }
});

// =========================
// WEBAUTHN – FINGERPRINT LOGIN
// =========================
const RP_NAME = "QejaConnect";
const RP_ID   = "eliyasande65-lang.github.io";
const ORIGIN  = "https://eliyasande65-lang.github.io";

const challenges = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of challenges.entries()) {
    if (now > val.expires) challenges.delete(key);
  }
}, 10 * 60 * 1000);

app.post("/auth/webauthn/register/start", async (req, res) => {
  try {
    const { userId, userName, userEmail } = req.body;
    const options = await generateRegistrationOptions({
      rpName:    RP_NAME,
      rpID:      RP_ID,
      userID:    new TextEncoder().encode(String(userId)),
      userName:  userEmail,
      userDisplayName: userName,
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification:        "required",
        residentKey:             "preferred",
      },
    });
    challenges.set(String(userId), {
      challenge: options.challenge,
      expires:   Date.now() + 5 * 60 * 1000,
    });
    res.json(options);
  } catch (err) {
    console.error("[WebAuthn register/start]", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/auth/webauthn/register/finish", async (req, res) => {
  try {
    const { userId, credential } = req.body;
    const entry = challenges.get(String(userId));
    if (!entry || Date.now() > entry.expires) {
      return res.status(400).json({ success: false, message: "Challenge expired. Try again." });
    }

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response:          credential,
      expectedChallenge: entry.challenge,
      expectedOrigin:    ORIGIN,
      expectedRPID:      RP_ID,
    });

    if (!verified) {
      return res.status(400).json({ success: false, message: "Verification failed" });
    }

    db.query(
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         credential_id=VALUES(credential_id),
         public_key=VALUES(public_key),
         counter=VALUES(counter)`,
      [
        parseInt(userId),
        Buffer.from(registrationInfo.credential.id, "base64url").toString("base64"),
        Buffer.from(registrationInfo.credential.publicKey),
        registrationInfo.credential.counter ?? 0,
      ],
      (err) => {
        if (err) {
          console.error("[WebAuthn DB save]", err.message);
          return res.status(500).json({ success: false, message: "Server error" });
        }
        challenges.delete(String(userId));
        res.json({ success: true });
      }
    );
  } catch (err) {
    console.error("[WebAuthn register/finish]", err.message);
    res.status(400).json({ success: false, message: "Server error" });
  }
});

app.post("/auth/webauthn/login/start", (req, res) => {
  const { userId } = req.body;
  db.query(
    "SELECT * FROM webauthn_credentials WHERE user_id = ?",
    [parseInt(userId)],
    async (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: "No fingerprint registered" });
      }

      try {
        const credIdBase64url = Buffer.from(rows[0].credential_id, "base64").toString("base64url");
        const options = await generateAuthenticationOptions({
          rpID:             RP_ID,
          userVerification: "required",
          allowCredentials: [{ id: credIdBase64url, type: "public-key" }],
        });
        challenges.set(String(userId), {
          challenge: options.challenge,
          expires:   Date.now() + 5 * 60 * 1000,
        });
        res.json(options);
      } catch (err2) {
        console.error("[WebAuthn login/start]", err2.message);
        res.status(500).json({ success: false, message: "Server error" });
      }
    }
  );
});

app.post("/auth/webauthn/login/finish", (req, res) => {
  const { userId, credential } = req.body;
  const entry = challenges.get(String(userId));
  if (!entry || Date.now() > entry.expires) {
    return res.status(400).json({ success: false, message: "Challenge expired. Try again." });
  }

  db.query(
    "SELECT * FROM webauthn_credentials WHERE user_id = ?",
    [parseInt(userId)],
    async (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: "Credential not found" });
      }

      try {
        const cred = rows[0];
        const { verified, authenticationInfo } = await verifyAuthenticationResponse({
          response:          credential,
          expectedChallenge: entry.challenge,
          expectedOrigin:    ORIGIN,
          expectedRPID:      RP_ID,
          authenticator: {
            credentialID:        new Uint8Array(Buffer.from(cred.credential_id, "base64")),
            credentialPublicKey: new Uint8Array(cred.public_key),
            counter:             cred.counter,
          },
        });

        if (!verified) {
          return res.status(401).json({ success: false, message: "Fingerprint verification failed" });
        }

        db.query(
          "UPDATE webauthn_credentials SET counter=? WHERE user_id=?",
          [authenticationInfo.newCounter, parseInt(userId)]
        );
        challenges.delete(String(userId));

        db.query("SELECT * FROM users WHERE id=?", [parseInt(userId)], (err2, users) => {
          if (err2) return res.status(500).json({ success: false, message: "Server error" });

          if (users.length > 0) {
            const user  = users[0];
            const token = jwt.sign(
              { id: user.id, role: "tenant" },
              process.env.JWT_SECRET,
              { expiresIn: "1d" }
            );
            const { password: _pw, ...safeUser } = user;
            return res.json({ success: true, role: "tenant", token, user: safeUser });
          }

          db.query("SELECT * FROM landlords WHERE id=?", [parseInt(userId)], (err3, landlords) => {
            if (err3) return res.status(500).json({ success: false, message: "Server error" });
            if (landlords.length === 0) {
              return res.status(404).json({ success: false, message: "User not found" });
            }
            const landlord = landlords[0];
            const token    = jwt.sign(
              { id: landlord.id, role: "landlord" },
              process.env.JWT_SECRET,
              { expiresIn: "1d" }
            );
            const { password: _pw, ...safeLandlord } = landlord;
            res.json({ success: true, role: "landlord", token, user: safeLandlord });
          });
        });
      } catch (err) {
        console.error("[WebAuthn login/finish]", err.message);
        res.status(400).json({ success: false, message: "Server error" });
      }
    }
  );
});

// =========================
// UPDATE PHONE
// =========================
app.patch("/update-phone", auth, (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: "Phone number required" });
  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Only landlords can update phone" });
  }

  db.query("UPDATE landlords SET phone=? WHERE id=?", [phone, req.user.id], (err) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, message: "Phone updated" });
  });
});

app.patch("/update-tenant-phone", auth, (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: "Phone number required" });
  if (req.user.role !== "tenant") {
    return res.status(403).json({ success: false, message: "Tenants only" });
  }

  db.query("UPDATE users SET phone=? WHERE id=?", [phone, req.user.id], (err) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    res.json({ success: true, message: "Phone updated" });
  });
});

// =========================
// UPLOAD TENANT PROFILE PIC
// =========================
app.post("/upload-tenant-pic", auth, upload.single("image"), (req, res) => {
  if (!req.file) return res.status(400).json({ success: false, message: "No image uploaded" });
  if (req.user.role !== "tenant") {
    return res.status(403).json({ success: false, message: "Tenants only" });
  }

  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: "qejaconnect_profiles" },
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "Upload failed" });
      db.query("UPDATE users SET profile_pic=? WHERE id=?", [result.secure_url, req.user.id], (err2) => {
        if (err2) return res.status(500).json({ success: false, message: "Server error" });
        res.json({ success: true, image: result.secure_url });
      });
    }
  );
  streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
});

// =========================
// ADMIN: CONTACT MESSAGES
// =========================
app.get("/admin/messages", adminAuth, (req, res) => {
  const page    = Math.max(1, parseInt(req.query.page)  || 1);
  const limit   = Math.min(100, parseInt(req.query.limit) || 20);
  const offset  = (page - 1) * limit;
  const replied = req.query.replied;

  let where  = "";
  let params = [];

  if (replied === "0") where = "WHERE cm.reply IS NULL";
  else if (replied === "1") where = "WHERE cm.reply IS NOT NULL";

  const countSql = `SELECT COUNT(*) AS total FROM contact_messages cm ${where}`;
  const dataSql  = `
    SELECT cm.id, cm.sender_id, cm.sender_role, cm.message, cm.reply,
           cm.replied_at, cm.created_at,
           CASE WHEN cm.sender_role='tenant'   THEN u.fullname
                WHEN cm.sender_role='landlord' THEN l.fullname ELSE 'Unknown' END AS sender_name,
           CASE WHEN cm.sender_role='tenant'   THEN u.email
                WHEN cm.sender_role='landlord' THEN l.email   ELSE NULL END AS sender_email
    FROM contact_messages cm
    LEFT JOIN users     u ON cm.sender_role='tenant'   AND cm.sender_id=u.id
    LEFT JOIN landlords l ON cm.sender_role='landlord' AND cm.sender_id=l.id
    ${where}
    ORDER BY cm.created_at DESC
    LIMIT ? OFFSET ?
  `;

  db.query(countSql, params, (err, countRows) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    db.query(dataSql, [...params, limit, offset], (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: "Server error" });
      res.json({ success: true, total: countRows[0].total, page, limit, messages: rows });
    });
  });
});

app.post("/admin/messages/:id/reply", adminAuth, (req, res) => {
  const { reply } = req.body;
  if (!reply || !reply.trim()) {
    return res.status(400).json({ success: false, message: "Reply text is required" });
  }
  db.query(
    `UPDATE contact_messages SET reply=?, replied_at=NOW() WHERE id=?`,
    [reply.trim(), req.params.id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Message not found" });
      }
      res.json({ success: true, message: "Reply sent" });
    }
  );
});

app.get("/my-messages", auth, (req, res) => {
  db.query(
    `SELECT id, message, reply, replied_at, created_at
     FROM contact_messages
     WHERE sender_id=? AND sender_role=?
     ORDER BY created_at DESC`,
    [req.user.id, req.user.role],
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      res.json({ success: true, messages: rows });
    }
  );
});

// =========================
// UPDATES
// =========================
app.get("/updates", (req, res) => {
  db.query(
    `SELECT id, title, body, type, image_url, cta_url, cta_label, created_at
     FROM updates ORDER BY created_at DESC LIMIT 50`,
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: "Server error" });
      res.json({ success: true, updates: rows });
    }
  );
});

app.post("/admin/updates", adminAuth, upload.single("image"), async (req, res) => {
  const { title, body, type, cta_url, cta_label } = req.body;
  if (!title || !body) {
    return res.status(400).json({ success: false, message: "title and body are required" });
  }

  const validTypes = ["announcement", "maintenance", "alert", "feature", "promotion"];
  const updateType = validTypes.includes(type) ? type : "announcement";

  try {
    let image_url = null;
    if (req.file) {
      image_url = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: "qejaconnect_updates" },
          (err, result) => {
            if (err) return reject(err);
            resolve(result.secure_url);
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(stream);
      });
    }

    db.query(
      `INSERT INTO updates (title, body, type, image_url, cta_url, cta_label)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [title.trim(), body.trim(), updateType, image_url, cta_url || null, cta_label || null],
      (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Server error" });
        res.json({ success: true, message: "Update published", id: result.insertId });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.delete("/admin/updates/:id", adminAuth, (req, res) => {
  db.query("DELETE FROM updates WHERE id=?", [req.params.id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "Server error" });
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Update not found" });
    }
    res.json({ success: true, message: "Update deleted" });
  });
});

// =========================
// BOOKINGS
// =========================
router.post("/bookings", auth, async (req, res) => {
  try {
    const { tenant_id, landlord_id, property_id, message } = req.body;
    if (!tenant_id || !landlord_id || !property_id) {
      return res.json({ success: false, message: "Missing required fields" });
    }

    const [existing] = await dbPromise.query(
      `SELECT id FROM bookings WHERE tenant_id=? AND property_id=? AND status='pending'`,
      [tenant_id, property_id]
    );
    if (existing.length) {
      return res.json({
        success: false,
        message: "You already have a pending booking for this property.",
      });
    }

    const [result] = await dbPromise.query(
      `INSERT INTO bookings (tenant_id, landlord_id, property_id, message) VALUES (?, ?, ?, ?)`,
      [tenant_id, landlord_id, property_id, message || "I would like to book this property."]
    );
    await logActivity(tenant_id, "tenant", "booked_property", { landlord_id, property_id }, req);
    res.json({ success: true, booking_id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/bookings/tenant/:id", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT b.*, p.title, p.location, p.price, p.image_url, p.description, p.type,
              l.fullname AS landlord_name, l.phone AS landlord_phone
       FROM bookings b
       JOIN properties p ON b.property_id=p.id
       JOIN landlords  l ON b.landlord_id=l.id
       WHERE b.tenant_id=?
       ORDER BY b.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, bookings: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/landlord/interests/:id", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT b.*, p.title AS property_title, p.location, p.price, p.image_url,
              t.fullname AS tenant_name, t.email AS tenant_email,
              ten.id AS tenancy_id, ten.rent_amount, ten.start_date
       FROM bookings b
       JOIN properties p  ON b.property_id=p.id
       JOIN users      t  ON b.tenant_id=t.id
       LEFT JOIN tenancies ten ON ten.booking_id=b.id
       WHERE b.landlord_id=?
       ORDER BY b.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/bookings/:id/approve", auth, async (req, res) => {
  try {
    await dbPromise.query(
      `UPDATE bookings SET status='approved' WHERE id=? AND landlord_id=?`,
      [req.params.id, req.body.landlord_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/bookings/:id/reject", auth, async (req, res) => {
  try {
    await dbPromise.query(
      `UPDATE bookings SET status='rejected' WHERE id=? AND landlord_id=?`,
      [req.params.id, req.body.landlord_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/bookings/:id/cancel", auth, async (req, res) => {
  try {
    await dbPromise.query(
      `UPDATE bookings SET status='rejected' WHERE id=? AND status='pending'`,
      [req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// WITHDRAWALS
// =========================
app.get("/admin/withdrawals", async (req, res) => {
  try {
    const status     = req.query.status || "pending";
    const statuses   = status.split(",");
    const placeholders = statuses.map(() => "?").join(",");

    const [rows] = await db.promise().query(
      `SELECT wr.*, l.fullname AS landlord_name, l.email AS landlord_email, l.phone AS landlord_phone
       FROM withdrawal_requests wr
       LEFT JOIN landlords l ON wr.landlord_id = l.id
       WHERE wr.status IN (${placeholders})
       ORDER BY wr.created_at DESC`,
      statuses
    );
    res.json({ success: true, withdrawals: rows });
  } catch (err) {
    console.error("Withdrawals fetch error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/withdrawals/:id/mark-paid", async (req, res) => {
  try {
    await db.promise().query(
      `UPDATE withdrawal_requests SET status='paid', paid_at=NOW() WHERE id=?`,
      [req.params.id]
    );
    res.json({ success: true, message: "Withdrawal marked as paid" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/withdrawals/:id/reject", async (req, res) => {
  try {
    const { admin_note } = req.body;
    await db.promise().query(
      `UPDATE withdrawal_requests SET status='rejected', admin_note=? WHERE id=?`,
      [admin_note || null, req.params.id]
    );
    res.json({ success: true, message: "Withdrawal rejected" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/admin/withdrawals/:id/note", async (req, res) => {
  try {
    const { admin_note } = req.body;
    await db.promise().query(
      `UPDATE withdrawal_requests SET admin_note=? WHERE id=?`,
      [admin_note, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post("/withdrawals/request", async (req, res) => {
  try {
    const { landlord_id, amount, method, phone, account_name, bank_details, note } = req.body;
    const [result] = await db.promise().query(
      `INSERT INTO withdrawal_requests
         (landlord_id, amount, method, phone, account_name, bank_details, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [landlord_id, amount, method, phone, account_name, bank_details, note]
    );
    res.json({ success: true, id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

app.get("/withdrawals/landlord/:landlordId", async (req, res) => {
  try {
    const [rows] = await db.promise().query(
      `SELECT * FROM withdrawal_requests WHERE landlord_id = ? ORDER BY created_at DESC`,
      [req.params.landlordId]
    );
    res.json({ success: true, withdrawals: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// =========================
// TENANCIES
// =========================
router.post("/tenancy/start", auth, async (req, res) => {
  try {
    const {
      booking_id, landlord_id, tenant_id, property_id,
      rent_amount, start_date, duration_months,
    } = req.body;

    if (!booking_id || !rent_amount || !start_date) {
      return res.json({ success: false, message: "Missing fields" });
    }

    const [existing] = await dbPromise.query(
      `SELECT id FROM tenancies WHERE booking_id=?`,
      [booking_id]
    );
    if (existing.length) {
      return res.json({
        success: false,
        message: "Tenancy session already started for this booking.",
      });
    }

    const [result] = await dbPromise.query(
      `INSERT INTO tenancies
         (booking_id, tenant_id, landlord_id, property_id,
          rent_amount, start_date, duration_months)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [booking_id, tenant_id, landlord_id, property_id,
       rent_amount, start_date, duration_months || 30]
    );

    await dbPromise.query(`UPDATE bookings SET status='active' WHERE id=?`, [booking_id]);
    res.json({ success: true, tenancy_id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/tenancy/tenant/:id", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT ten.*, p.title AS property_title, p.location, p.image_url,
              l.fullname AS landlord_name, l.phone AS landlord_phone,
              t.fullname AS tenant_name
       FROM tenancies ten
       JOIN properties p ON ten.property_id=p.id
       JOIN landlords  l ON ten.landlord_id=l.id
       JOIN users      t ON ten.tenant_id=t.id
       WHERE ten.tenant_id=? AND ten.status='active'
       LIMIT 1`,
      [req.params.id]
    );
    if (!rows.length) return res.json({ success: false, message: "No active tenancy" });

    const [payments] = await dbPromise.query(
      `SELECT * FROM rent_payments WHERE tenancy_id=? ORDER BY month_index ASC`,
      [rows[0].id]
    );
    rows[0].payments = payments;
    res.json({ success: true, tenancy: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/tenancy/landlord/:id", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT ten.*, p.title AS property_title, p.location,
              t.fullname AS tenant_name, t.email AS tenant_email
       FROM tenancies ten
       JOIN properties p ON ten.property_id=p.id
       JOIN users      t ON ten.tenant_id=t.id
       WHERE ten.landlord_id=?
       ORDER BY ten.created_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, tenancies: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/tenancy/payment-confirm", auth, async (req, res) => {
  try {
    const { tenancy_id, landlord_id, tenant_id, month_index, mpesa_ref, amount } = req.body;

    await dbPromise.query(
      `INSERT INTO rent_payments
         (tenancy_id, tenant_id, landlord_id,
          month_index, month_number, amount, mpesa_ref, status, paid_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'paid', NOW())
       ON DUPLICATE KEY UPDATE mpesa_ref=VALUES(mpesa_ref), status='paid', paid_at=NOW()`,
      [tenancy_id, tenant_id, landlord_id, month_index, month_index + 1, amount, mpesa_ref]
    );

    const [paymentRows] = await dbPromise.query(
      `SELECT id FROM rent_payments WHERE tenancy_id=? AND month_index=?`,
      [tenancy_id, month_index]
    );
    const rent_payment_id = paymentRows[0]?.id;

    const [tenantRows] = await dbPromise.query(
      `SELECT referred_by FROM users WHERE id=?`,
      [tenant_id]
    );
    const referredByCode = tenantRows[0]?.referred_by;

    if (referredByCode && rent_payment_id) {
      const [referrerRows] = await dbPromise.query(
        `SELECT id FROM users WHERE referral_code=?`,
        [referredByCode]
      );
      if (referrerRows.length) {
        const referrer_id  = referrerRows[0].id;
        const rewardAmount = (parseFloat(amount) * 0.01).toFixed(2);
        await dbPromise.query(
          `INSERT INTO referral_earnings
             (referrer_id, referred_id, tenancy_id, rent_payment_id,
              month_index, rent_amount, reward_amount, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
           ON DUPLICATE KEY UPDATE reward_amount=VALUES(reward_amount)`,
          [referrer_id, tenant_id, tenancy_id, rent_payment_id, month_index, amount, rewardAmount]
        );
      }
    }
    await logActivity(tenant_id, "tenant", "paid_rent", { tenancy_id, month_index, amount }, req);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// PAYMENTS (landlord side)
// =========================
router.get("/landlord/payments/:id", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT rp.*, t.fullname AS tenant_name,
              p.title AS property_title, p.location
       FROM rent_payments rp
       JOIN users      t   ON rp.tenant_id=t.id
       JOIN tenancies  ten ON rp.tenancy_id=ten.id
       JOIN properties p   ON ten.property_id=p.id
       WHERE rp.landlord_id=?
       ORDER BY rp.paid_at DESC`,
      [req.params.id]
    );
    res.json({ success: true, payments: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/payments/:id/confirm", auth, async (req, res) => {
  try {
    await dbPromise.query(
      `UPDATE rent_payments SET landlord_confirmed=1 WHERE id=? AND landlord_id=?`,
      [req.params.id, req.body.landlord_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/mpesa/status/:checkoutRequestId", auth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT status, transaction_id, amount, phone, result_desc
       FROM mpesa_payments WHERE checkout_request_id=? LIMIT 1`,
      [req.params.checkoutRequestId]
    );
    if (!rows.length) return res.json({ status: "pending" });
    const r = rows[0];

    if (r.status === "completed" || r.status === "used") {
      return res.json({
        status: "completed",
        paid:   true,
        mpesa_ref:             r.transaction_id,
        MpesaReceiptNumber:    r.transaction_id,
      });
    }
    if (r.status === "failed") return res.json({ status: "failed", message: r.result_desc });
    return res.json({ status: "pending" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ status: "pending" });
  }
});

// =========================
// ADMIN: REFERRALS
// =========================
router.get("/admin/referrals", adminAuth, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page)  || 1);
    const limit  = Math.min(100, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;
    const status = req.query.status;
    const search = (req.query.search || "").trim();

    const where  = [];
    const params = [];

    if (status === "pending" || status === "paid") {
      where.push("re.status=?");
      params.push(status);
    }
    if (search) {
      where.push(
        "(referrer.fullname LIKE ? OR referrer.email LIKE ? OR referrer.referral_code LIKE ? OR referred.fullname LIKE ?)"
      );
      params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const [countRows] = await dbPromise.query(
      `SELECT COUNT(*) AS total FROM referral_earnings re
       JOIN users referrer ON re.referrer_id=referrer.id
       JOIN users referred ON re.referred_id=referred.id ${whereSql}`,
      params
    );

    const [rows] = await dbPromise.query(
      `SELECT re.id, re.tenancy_id, re.month_index, re.rent_amount, re.reward_amount,
              re.status, re.paid_at, re.created_at,
              referrer.id AS referrer_id, referrer.fullname AS referrer_name,
              referrer.email AS referrer_email, referrer.phone AS referrer_phone,
              referrer.referral_code,
              referred.id AS referred_id, referred.fullname AS referred_name,
              referred.email AS referred_email
       FROM referral_earnings re
       JOIN users referrer ON re.referrer_id=referrer.id
       JOIN users referred ON re.referred_id=referred.id
       ${whereSql}
       ORDER BY re.created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    const [summaryRows] = await dbPromise.query(
      `SELECT
         COALESCE(SUM(re.reward_amount),0) AS totalReward,
         COALESCE(SUM(CASE WHEN re.status='paid'    THEN re.reward_amount ELSE 0 END),0) AS totalPaid,
         COALESCE(SUM(CASE WHEN re.status='pending' THEN re.reward_amount ELSE 0 END),0) AS totalPending,
         COUNT(DISTINCT re.referrer_id) AS activeReferrers
       FROM referral_earnings re
       JOIN users referrer ON re.referrer_id=referrer.id
       JOIN users referred ON re.referred_id=referred.id ${whereSql}`,
      params
    );

    res.json({
      success: true,
      total:   countRows[0].total,
      page,
      limit,
      summary: summaryRows[0],
      referrals: rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.patch("/admin/referrals/:id/pay", adminAuth, async (req, res) => {
  try {
    const [result] = await dbPromise.query(
      `UPDATE referral_earnings SET status='paid', paid_at=NOW()
       WHERE id=? AND status='pending'`,
      [req.params.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Earning not found or already paid" });
    }
    res.json({ success: true, message: "Marked as paid" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.get("/admin/referrals/leaderboard", adminAuth, async (req, res) => {
  try {
    const limit = Math.min(100, parseInt(req.query.limit) || 20);
    const [rows] = await dbPromise.query(
      `SELECT u.id, u.fullname, u.email, u.phone, u.referral_code,
              COUNT(re.id) AS referral_count,
              COALESCE(SUM(re.reward_amount),0) AS totalEarned,
              COALESCE(SUM(CASE WHEN re.status='paid'    THEN re.reward_amount ELSE 0 END),0) AS totalPaid,
              COALESCE(SUM(CASE WHEN re.status='pending' THEN re.reward_amount ELSE 0 END),0) AS totalPending
       FROM users u
       JOIN referral_earnings re ON re.referrer_id=u.id
       GROUP BY u.id
       ORDER BY totalEarned DESC
       LIMIT ?`,
      [limit]
    );
    res.json({ success: true, leaderboard: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// =========================
// MOUNT ROUTER & ERROR HANDLER
// =========================
app.use(router);

app.use((err, req, res, next) => {
  console.error("[UNHANDLED ERROR]", err.message);
  res
    .status(err.status || 500)
    .json({ success: false, message: "Something went wrong. Please try again." });
});

// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
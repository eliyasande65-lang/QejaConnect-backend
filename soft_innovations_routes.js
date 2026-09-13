/*
 * SOFT INNOVATIONS API ROUTES
 * Paste this block into your existing QejaConnect server.js AFTER:
 *   - dbPromise is created
 *   - validate(), auth(), adminAuth(), generalLimiter and z are defined
 * and BEFORE app.use(router) / the global error handler.
 *
 * Frontend base API:
 *   https://qeja-backend-azkf.onrender.com
 *
 * Routes intentionally use /soft/* so they do not collide with existing
 * QejaConnect routes such as POST /contact.
 *
 * ---------------------------------------------------------------------
 * UPDATE — added signup, login, feedback lookup, and a "me" route.
 * These were referenced by the frontend (public/js/main.js,
 * public/feedback.html) but had no matching backend route.
 *
 * NEW REQUIREMENTS:
 *   npm install bcryptjs jsonwebtoken
 *   (skip whichever your QejaConnect server.js already installs/requires
 *   under a different variable name — just reuse that require instead
 *   of adding a second one)
 *
 * NEW ENV VAR:
 *   SOFT_JWT_SECRET   a long random string, separate from any secret
 *                     QejaConnect's own auth() middleware uses. Soft
 *                     Innovations client accounts live in a different
 *                     table (softusers) with a different shape than
 *                     QejaConnect's tenant/landlord users, so tokens are
 *                     signed and verified with their own secret and
 *                     their own middleware (softAuth below) to avoid any
 *                     cross-verification between the two systems.
 *
 * NEW TABLE:
 *   Run signup_package/softusers.sql against the same database before
 *   testing these routes.
 * ---------------------------------------------------------------------
 */

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const SOFT_JWT_SECRET = process.env.SOFT_JWT_SECRET;

if (!SOFT_JWT_SECRET) {
  // Fail loudly at startup rather than silently signing tokens with
  // "undefined" — a common source of forgeable-token bugs.
  console.warn("[SOFT] WARNING: SOFT_JWT_SECRET is not set. /soft/signup and /soft/login will fail.");
}

function signSoftToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name, is_admin: !!user.is_admin },
    SOFT_JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// softAuth verifies a Soft Innovations client token (from softusers).
// Kept separate from QejaConnect's own auth() middleware — different
// user table, different token shape, different secret.
function softAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, message: "Login required." });
  }

  try {
    req.softUser = jwt.verify(token, SOFT_JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired session." });
  }
}

const softSignupSchema = z.object({
  name: z.string().trim().min(2).max(150),
  email: z.string().trim().email().max(150),
  password: z.string().min(6).max(200)
});

const softLoginSchema = z.object({
  email: z.string().trim().email().max(150),
  password: z.string().min(1).max(200)
});

const softOrderSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.string().email().max(150),
  service: z.string().trim().min(2).max(80).optional(),
  website_type: z.string().trim().max(120).optional(),
  description: z.string().trim().min(5).max(5000).optional(),
  inclusions: z.string().trim().max(5000).optional(),
  plan: z.string().trim().max(100).optional(),
  estimated_price: z.coerce.number().min(0).max(100000000).optional(),
  storage: z.array(z.string().max(30)).max(10).optional()
}).refine(data => data.description || data.website_type || data.service, {
  message: "Please describe the service or project you need."
});

const softContactSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: z.string().email().max(150),
  message: z.string().trim().min(5).max(5000)
});

const softTrackSchema = z.string().trim().min(3).max(40).regex(/^SI-[A-Z0-9-]+$/i, "Invalid project ID");

// ---------------------------------------------------------
// POST /soft/contact
// Public contact form used by Soft Innovations.
// ---------------------------------------------------------
app.post("/soft/contact", generalLimiter, validate(softContactSchema), async (req, res) => {
  try {
    const { name, email, message } = req.body;

    const [result] = await dbPromise.query(
      `INSERT INTO soft_contact_messages (name, email, message)
       VALUES (?, ?, ?)`,
      [name, email, message]
    );

    res.status(201).json({
      success: true,
      message: "Message received successfully.",
      id: result.insertId
    });
  } catch (err) {
    console.error("[SOFT CONTACT]", err.message);
    res.status(500).json({ success: false, message: "Could not send your message." });
  }
});

// ---------------------------------------------------------
// POST /soft/orders
// Public project/order request.
// Generates a human-friendly ID such as SI-1042.
// ---------------------------------------------------------
app.post("/soft/orders", generalLimiter, validate(softOrderSchema), async (req, res) => {
  try {
    const {
      name, email, service = null, website_type = null,
      description = null, inclusions = null, plan = null,
      estimated_price = 0, storage = []
    } = req.body;

    const storageJson = JSON.stringify(storage || []);

    const [result] = await dbPromise.query(
      `INSERT INTO soft_orders
       (customer_name, customer_email, service, website_type, description,
        inclusions, plan_name, estimated_price, storage_options, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'received')`,
      [name, email, service, website_type, description, inclusions,
       plan, estimated_price, storageJson]
    );

    const orderId = `SI-${1000 + result.insertId}`;

    await dbPromise.query(
      `UPDATE soft_orders SET order_code=? WHERE id=?`,
      [orderId, result.insertId]
    );

    res.status(201).json({
      success: true,
      message: "Project request received successfully.",
      order_id: orderId,
      id: result.insertId,
      status: "received"
    });
  } catch (err) {
    console.error("[SOFT ORDER]", err.message);
    res.status(500).json({ success: false, message: "Could not create the project request." });
  }
});

// ---------------------------------------------------------
// GET /soft/orders/:orderCode
// Public project tracking.
// Only exposes safe customer-facing fields.
// ---------------------------------------------------------
app.get("/soft/orders/:orderCode", generalLimiter, async (req, res) => {
  try {
    const orderCode = String(req.params.orderCode).trim().toUpperCase();
    const parsed = softTrackSchema.safeParse(orderCode);

    if (!parsed.success) {
      return res.status(400).json({ success: false, message: "Invalid project ID." });
    }

    const [rows] = await dbPromise.query(
      `SELECT order_code, customer_name, service, website_type, plan_name,
              status, customer_message, created_at, updated_at
       FROM soft_orders
       WHERE order_code=?
       LIMIT 1`,
      [orderCode]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    const project = rows[0];
    res.json({
      success: true,
      order_id: project.order_code,
      project_name: project.website_type || project.service || "Soft Innovations Project",
      status: project.status,
      message: project.customer_message || statusMessage(project.status),
      service: project.service,
      plan: project.plan_name,
      created_at: project.created_at,
      updated_at: project.updated_at
    });
  } catch (err) {
    console.error("[SOFT TRACK]", err.message);
    res.status(500).json({ success: false, message: "Could not retrieve project status." });
  }
});

function statusMessage(status) {
  const messages = {
    received: "Your project request has been received and is awaiting review.",
    reviewing: "Your project is being reviewed and scoped.",
    quoted: "Your project has been reviewed and a quotation is being prepared.",
    approved: "Your project has been approved and is ready for development.",
    development: "Development is currently in progress.",
    testing: "Your project is currently being tested and refined.",
    ready: "Your project is ready for delivery or launch.",
    completed: "Your project has been completed.",
    cancelled: "This project request has been cancelled."
  };
  return messages[status] || "Your project status is being updated.";
}

// ---------------------------------------------------------
// POST /soft/signup
// Creates a Soft Innovations client account (separate from
// QejaConnect's own users) and returns a session token.
// ---------------------------------------------------------
app.post("/soft/signup", generalLimiter, validate(softSignupSchema), async (req, res) => {
  try {
    const { name, password } = req.body;
    const email = String(req.body.email).trim().toLowerCase();

    const [existing] = await dbPromise.query(
      `SELECT id FROM softusers WHERE email=? LIMIT 1`,
      [email]
    );

    if (existing.length) {
      return res.status(409).json({ success: false, message: "An account with this email already exists." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const [result] = await dbPromise.query(
      `INSERT INTO softusers (name, email, password_hash) VALUES (?, ?, ?)`,
      [name, email, passwordHash]
    );

    const user = { id: result.insertId, name, email, is_admin: 0 };
    const token = signSoftToken(user);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user: { id: user.id, name: user.name, email: user.email, is_admin: false }
    });
  } catch (err) {
    console.error("[SOFT SIGNUP]", err.message);
    res.status(500).json({ success: false, message: "Could not create your account." });
  }
});

// ---------------------------------------------------------
// POST /soft/login
// ---------------------------------------------------------
app.post("/soft/login", generalLimiter, validate(softLoginSchema), async (req, res) => {
  try {
    const email = String(req.body.email).trim().toLowerCase();
    const { password } = req.body;

    const [rows] = await dbPromise.query(
      `SELECT id, name, email, password_hash, is_admin FROM softusers WHERE email=? LIMIT 1`,
      [email]
    );

    // Same generic message whether the email is unknown or the password
    // is wrong, so the endpoint doesn't leak which emails have accounts.
    if (!rows.length) {
      return res.status(401).json({ success: false, message: "Invalid email or password." });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid email or password." });
    }

    const token = signSoftToken(user);

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: { id: user.id, name: user.name, email: user.email, is_admin: !!user.is_admin }
    });
  } catch (err) {
    console.error("[SOFT LOGIN]", err.message);
    res.status(500).json({ success: false, message: "Could not log you in." });
  }
});

// ---------------------------------------------------------
// GET /soft/me
// Returns the logged-in Soft Innovations client's own profile.
// ---------------------------------------------------------
app.get("/soft/me", softAuth, async (req, res) => {
  try {
    const [rows] = await dbPromise.query(
      `SELECT id, name, email, is_admin, created_at FROM softusers WHERE id=? LIMIT 1`,
      [req.softUser.id]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: "Account not found." });
    }

    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("[SOFT ME]", err.message);
    res.status(500).json({ success: false, message: "Could not load your profile." });
  }
});

// ---------------------------------------------------------
// GET /soft/feedback/:email
// Public lookup used by public/feedback.html. Combines admin
// contact-message replies with order status updates for one email.
// Intentionally public (no login required) to match how the frontend
// currently calls it — matching /soft/orders/:orderCode's pattern of
// exposing only safe, non-sensitive fields.
// ---------------------------------------------------------
app.get("/soft/feedback/:email", generalLimiter, async (req, res) => {
  try {
    const email = String(req.params.email).trim().toLowerCase();
    const parsed = z.string().trim().email().max(150).safeParse(email);

    if (!parsed.success) {
      return res.status(400).json({ success: false, message: "Invalid email address." });
    }

    const [contactReplies] = await dbPromise.query(
      `SELECT 'Message reply' AS title, reply AS message, replied_at AS created_at
       FROM soft_contact_messages
       WHERE email=? AND reply IS NOT NULL
       ORDER BY replied_at DESC`,
      [email]
    );

    const [orderUpdates] = await dbPromise.query(
      `SELECT CONCAT('Project ', order_code, ' — ', status) AS title,
              customer_message AS message, updated_at AS created_at
       FROM soft_orders
       WHERE customer_email=? AND customer_message IS NOT NULL
       ORDER BY updated_at DESC`,
      [email]
    );

    const replies = [...contactReplies, ...orderUpdates].sort(
      (a, b) => new Date(b.created_at) - new Date(a.created_at)
    );

    res.json({ success: true, total: replies.length, replies });
  } catch (err) {
    console.error("[SOFT FEEDBACK]", err.message);
    res.status(500).json({ success: false, message: "Could not load feedback." });
  }
});

// ---------------------------------------------------------
// ADMIN: GET /admin/soft/orders
// Add to an existing admin dashboard later.
// ---------------------------------------------------------
app.get("/admin/soft/orders", adminAuth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
    const offset = (page - 1) * limit;
    const status = String(req.query.status || "").trim();
    const search = String(req.query.search || "").trim();

    const conditions = [];
    const params = [];

    if (status) {
      conditions.push("status=?");
      params.push(status);
    }
    if (search) {
      conditions.push("(order_code LIKE ? OR customer_name LIKE ? OR customer_email LIKE ? OR website_type LIKE ?)");
      const q = `%${search}%`;
      params.push(q, q, q, q);
    }

    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

    const [countRows] = await dbPromise.query(
      `SELECT COUNT(*) AS total FROM soft_orders ${where}`,
      params
    );

    const [orders] = await dbPromise.query(
      `SELECT id, order_code, customer_name, customer_email, service,
              website_type, plan_name, estimated_price, status,
              created_at, updated_at
       FROM soft_orders
       ${where}
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );

    res.json({
      success: true,
      total: countRows[0].total,
      page,
      limit,
      orders
    });
  } catch (err) {
    console.error("[ADMIN SOFT ORDERS]", err.message);
    res.status(500).json({ success: false, message: "Could not load Soft Innovations orders." });
  }
});

// ---------------------------------------------------------
// ADMIN: PATCH /admin/soft/orders/:id/status
// ---------------------------------------------------------
app.patch("/admin/soft/orders/:id/status", adminAuth, async (req, res) => {
  try {
    const validStatuses = [
      "received", "reviewing", "quoted", "approved",
      "development", "testing", "ready", "completed", "cancelled"
    ];

    const status = String(req.body.status || "").trim();
    const customerMessage = req.body.customer_message
      ? String(req.body.customer_message).trim().slice(0, 2000)
      : null;

    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Allowed: ${validStatuses.join(", ")}`
      });
    }

    const [result] = await dbPromise.query(
      `UPDATE soft_orders
       SET status=?, customer_message=COALESCE(?, customer_message), updated_at=NOW()
       WHERE id=?`,
      [status, customerMessage, req.params.id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ success: false, message: "Project not found." });
    }

    res.json({ success: true, message: "Project status updated.", status });
  } catch (err) {
    console.error("[ADMIN SOFT ORDER STATUS]", err.message);
    res.status(500).json({ success: false, message: "Could not update project status." });
  }
});

// ---------------------------------------------------------
// ADMIN: GET /admin/soft/contact-messages
// ---------------------------------------------------------
app.get("/admin/soft/contact-messages", adminAuth, async (req, res) => {
  try {
    const [messages] = await dbPromise.query(
      `SELECT id, name, email, message, reply, replied_at, created_at
       FROM soft_contact_messages
       ORDER BY created_at DESC
       LIMIT 100`
    );
    res.json({ success: true, messages });
  } catch (err) {
    console.error("[ADMIN SOFT CONTACT]", err.message);
    res.status(500).json({ success: false, message: "Could not load messages." });
  }
});

// ---------------------------------------------------------
// ADMIN: POST /admin/soft/contact-messages/:id/reply
// ---------------------------------------------------------
app.post("/admin/soft/contact-messages/:id/reply", adminAuth, async (req, res) => {
  try {
    const reply = String(req.body.reply || "").trim();
    if (!reply) return res.status(400).json({ success: false, message: "Reply is required." });

    const [result] = await dbPromise.query(
      `UPDATE soft_contact_messages
       SET reply=?, replied_at=NOW()
       WHERE id=?`,
      [reply.slice(0, 5000), req.params.id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({ success: false, message: "Message not found." });
    }

    res.json({ success: true, message: "Reply saved." });
  } catch (err) {
    console.error("[ADMIN SOFT CONTACT REPLY]", err.message);
    res.status(500).json({ success: false, message: "Could not save reply." });
  }
});

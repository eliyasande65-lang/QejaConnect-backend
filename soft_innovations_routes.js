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
 */

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

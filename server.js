require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const streamifier = require("streamifier");
const cloudinary = require("cloudinary").v2;
const OpenAI = require("openai");

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});
const app = express();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// =========================
// MIDDLEWARE
// =========================
app.use(cors({ origin: "*" }));
app.use(express.json());

// =========================
// DB — USE POOL (fixes timeout/reconnect issues)
// =========================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

db.getConnection((err, connection) => {
  if (err) console.log("DB Error:", err.message);
  else {
    console.log("MySQL Pool Connected ✅");
    connection.release();
  }
});

// =========================
// MULTER MEMORY STORAGE
// =========================
const storage = multer.memoryStorage();
const upload = multer({ storage });

// =========================
// AUTH MIDDLEWARE
// =========================
function auth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ message: "No token" });
  }

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
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

// =========================
// ROOT
// =========================
app.get("/", (req, res) => {
  res.json({ message: "QejaConnect API running 🚀" });
});

// =========================
// SIGNUP
// =========================
app.post("/signup", async (req, res) => {
  const { fullname, email, password } = req.body;

  if (!fullname || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields required" });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, message: "Password must be at least 6 characters" });
  }

  const hashed = await bcrypt.hash(password, 10);
  const sql = `INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)`;

  db.query(sql, [fullname, email, hashed], (err) => {
    if (err) {
      return res.status(500).json({ success: false, message: err.sqlMessage });
    }
    res.json({ success: true, message: "User created" });
  });
});

// =========================
// LOGIN
// =========================
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password required" });
  }

  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, users) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    if (users.length > 0) {
      const user = users[0];
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
      return res.json({ success: true, role: "tenant", token, user: safeUser });
    }

    db.query("SELECT * FROM landlords WHERE email = ?", [email], async (err, landlords) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      if (landlords.length === 0) {
        return res.status(401).json({ success: false, message: "User not found" });
      }

      const landlord = landlords[0];
      const valid = await bcrypt.compare(password, landlord.password);
      if (!valid) {
        return res.status(401).json({ success: false, message: "Wrong password" });
      }

      const token = jwt.sign(
        { id: landlord.id, role: "landlord" },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );

      const { password: _pw, ...safeLandlord } = landlord;
      res.json({ success: true, role: "landlord", token, user: safeLandlord });
    });
  });
});

// =========================
// GET ALL PROPERTIES — verified landlords only
// =========================
app.get("/properties", (req, res) => {
  const sql = `
    SELECT p.*, l.fullname AS landlord_name
    FROM properties p
    LEFT JOIN landlords l ON p.landlord_id = l.id
    WHERE l.verified = 1
    ORDER BY p.id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, properties: results });
  });
});


// =========================
// GET PROPERTIES BY LANDLORD ID
// =========================
app.get("/landlord-properties/:id", auth, (req, res) => {
  const landlord_id = req.params.id;

  const sql = `
    SELECT id, title, price, location, type, listing_expires_at, created_at
    FROM properties
    WHERE landlord_id = ?
    ORDER BY id DESC
  `;

  db.query(sql, [landlord_id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, properties: results });
  });
});
// =========================
// GET ALL LANDLORDS — verified only
// =========================
app.get("/landlords", (req, res) => {
  const sql = `
    SELECT id, fullname, email, town, county, profile_pic, property_name
    FROM landlords
    WHERE verified = 1
    ORDER BY id DESC
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, landlords: results });
  });
});

// =========================
// GET SINGLE LANDLORD BY ID — verified only
// =========================
app.get("/landlords/:id", (req, res) => {
  const { id } = req.params;

  const sql = `
    SELECT id, fullname, email, phone, town, county,
           profile_pic, property_name, property_type,
           units, description
    FROM landlords
    WHERE id = ? AND verified = 1
  `;

  db.query(sql, [id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Landlord not found" });
    }

    res.json({ success: true, landlord: results[0] });
  });
});

// =========================
// INTERESTED → START CHAT
// =========================
app.post("/interested", auth, (req, res) => {
  const { landlord_id, tenant_id, message } = req.body;

  if (!landlord_id || !tenant_id) {
    return res.status(400).json({ success: false, message: "landlord_id and tenant_id required" });
  }

  const checkSql = `
    SELECT * FROM conversations
    WHERE landlord_id = ? AND tenant_id = ?
  `;

  db.query(checkSql, [landlord_id, tenant_id], (err, existing) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    if (existing.length > 0) {
      const conversation_id = existing[0].id;

      const insertChat = `
        INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
        VALUES (?, ?, ?, 'tenant', ?)
      `;

      db.query(insertChat, [conversation_id, landlord_id, tenant_id, message], (err2) => {
        if (err2) return res.status(500).json({ success: false, message: err2.message });
        res.json({ success: true, message: "Chat started", conversation_id });
      });

    } else {
      const createConversation = `
        INSERT INTO conversations (landlord_id, tenant_id) VALUES (?, ?)
      `;

      db.query(createConversation, [landlord_id, tenant_id], (err3, result) => {
        if (err3) return res.status(500).json({ success: false, message: err3.message });

        const conversation_id = result.insertId;

        const insertChat = `
          INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
          VALUES (?, ?, ?, 'tenant', ?)
        `;

        db.query(insertChat, [conversation_id, landlord_id, tenant_id, message], (err4) => {
          if (err4) return res.status(500).json({ success: false, message: err4.message });
          res.json({ success: true, message: "Chat started", conversation_id });
        });
      });
    }
  });
});

// =========================
// LANDLORD CHATS
// =========================
app.get("/landlord-chats/:id", auth, (req, res) => {
  const landlord_id = req.params.id;

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

  db.query(sql, [landlord_id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, chats: results });
  });
});

// =========================
// TENANT CHATS
// =========================
app.get("/tenant-chats/:id", auth, (req, res) => {
  const tenant_id = req.params.id;

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

  db.query(sql, [tenant_id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, chats: results });
  });
});

// =========================
// SEND MESSAGE
// =========================
app.post("/send-message", auth, (req, res) => {
  const { conversation_id, landlord_id, tenant_id, sender_role, message } = req.body;

  if (!conversation_id || !landlord_id || !tenant_id || !sender_role || !message) {
    return res.status(400).json({ success: false, message: "All fields required" });
  }

  if (!["landlord", "tenant"].includes(sender_role)) {
    return res.status(400).json({ success: false, message: "Invalid sender_role" });
  }

  const sql = `
    INSERT INTO chats (conversation_id, landlord_id, tenant_id, sender_role, message)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(sql, [conversation_id, landlord_id, tenant_id, sender_role, message], (err) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, message: "Message sent" });
  });
});

// =========================
// CONTACT MESSAGE
// =========================
app.post("/contact", auth, (req, res) => {
  const { message } = req.body;
  const sender_id = req.user.id;
  const sender_role = req.user.role;

  if (!message) {
    return res.status(400).json({ success: false, message: "Message is required" });
  }

  const sql = `
    INSERT INTO contact_messages (sender_id, sender_role, message)
    VALUES (?, ?, ?)
  `;

  db.query(sql, [sender_id, sender_role, message], (err) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, message: "Message sent to support" });
  });
});

// =========================
// GET MESSAGES IN A CONVERSATION
// =========================
app.get("/messages/:conversation_id", auth, (req, res) => {
  const conversation_id = req.params.conversation_id;
  const user_id = req.user.id;

  const checkSql = `
    SELECT * FROM conversations
    WHERE id = ? AND (landlord_id = ? OR tenant_id = ?)
  `;

  db.query(checkSql, [conversation_id, user_id, user_id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    if (result.length === 0) {
      return res.status(403).json({ success: false, message: "Not allowed to access this chat" });
    }

    const sql = `SELECT * FROM chats WHERE conversation_id = ? ORDER BY id ASC`;

    db.query(sql, [conversation_id], (err2, messages) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });

      const conv = result[0];
      res.json({
        success: true,
        messages,
        landlord_id: conv.landlord_id,
        tenant_id: conv.tenant_id
      });
    });
  });
});

// =========================
// UPLOAD LANDLORD PROFILE PIC
// =========================
app.post("/upload-profile-pic", auth, upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "No image uploaded" });
  }

  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: "qejaconnect_profiles" },
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      const imageUrl = result.secure_url;
      const sql = `UPDATE landlords SET profile_pic = ? WHERE id = ?`;

      db.query(sql, [imageUrl, req.user.id], (err2) => {
        if (err2) return res.status(500).json({ success: false, message: err2.message });
        res.json({ success: true, image: imageUrl });
      });
    }
  );

  streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
});

// =========================
// REGISTER LANDLORD
// =========================
app.post("/register-landlord",
  upload.fields([
    { name: "profile_pic", maxCount: 1 },
    { name: "id_photo",    maxCount: 1 }
  ]),
  async (req, res) => {
    try {
      const {
        fullname, email, phone, id, kra, county,
        town, property, type, units, description, password
      } = req.body;

      const profileFile = req.files?.["profile_pic"]?.[0];
      const idFile      = req.files?.["id_photo"]?.[0];

      if (!profileFile) {
        return res.status(400).json({ success: false, message: "Profile image required" });
      }
      if (!idFile) {
        return res.status(400).json({ success: false, message: "National ID photo required" });
      }
      if (!fullname || !email || !password) {
        return res.status(400).json({ success: false, message: "fullname, email and password are required" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      function uploadToCloudinary(buffer, folder) {
        return new Promise((resolve, reject) => {
          const stream = cloudinary.uploader.upload_stream(
            { folder },
            (err, result) => {
              if (err) return reject(err);
              resolve(result.secure_url);
            }
          );
          streamifier.createReadStream(buffer).pipe(stream);
        });
      }

      const [profile_pic_url, id_photo_url] = await Promise.all([
        uploadToCloudinary(profileFile.buffer, "qejaconnect_profiles"),
        uploadToCloudinary(idFile.buffer,      "qejaconnect_ids")
      ]);

      const sql = `
        INSERT INTO landlords
          (fullname, email, phone, national_id, kra_pin, county, town,
           property_name, property_type, units, description,
           profile_pic, id_photo, password, verified)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
      `;

      db.query(
        sql,
        [
          fullname, email, phone, id, kra, county, town,
          property, type, units, description,
          profile_pic_url, id_photo_url, hashedPassword
        ],
        (err2) => {
          if (err2) return res.status(500).json({ success: false, message: err2.sqlMessage || err2.message });
          res.json({ success: true, message: "Landlord registered" });
        }
      );

    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  }
);

// =========================
// ADMIN: LIST ALL LANDLORDS (paginated)
// GET /admin/landlords?page=1&limit=20&verified=0
// =========================
app.get("/admin/landlords", adminAuth, (req, res) => {
  const page     = Math.max(1, parseInt(req.query.page)  || 1);
  const limit    = Math.min(100, parseInt(req.query.limit) || 20);
  const offset   = (page - 1) * limit;
  const verified = req.query.verified; // '0', '1', '-1', or undefined (all)

  let where  = "";
  let params = [];

  if (verified === "0" || verified === "1" || verified === "-1") {
    where  = "WHERE verified = ?";
    params = [parseInt(verified)];
  }

  const countSql = `SELECT COUNT(*) AS total FROM landlords ${where}`;
  const dataSql  = `
    SELECT
      id, fullname, email, phone, national_id, kra_pin,
      county, town, property_name, property_type,
      units, description, profile_pic, id_photo,
      verified, created_at
    FROM landlords
    ${where}
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `;

  db.query(countSql, params, (err, countRows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    const total = countRows[0].total;

    db.query(dataSql, [...params, limit, offset], (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });

      res.json({ success: true, total, page, limit, landlords: rows });
    });
  });
});

// =========================
// ADMIN: APPROVE OR REJECT A LANDLORD
// PATCH /admin/landlords/:id/verify
// Body: { "action": "approve" | "reject" }
// =========================
app.patch("/admin/landlords/:id/verify", adminAuth, (req, res) => {
  const { id }     = req.params;
  const { action } = req.body;

  if (!["approve", "reject"].includes(action)) {
    return res.status(400).json({ success: false, message: 'action must be "approve" or "reject"' });
  }

  const verified = action === "approve" ? 1 : -1; // -1 = rejected

  db.query(
    "UPDATE landlords SET verified = ? WHERE id = ?",
    [verified, id],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      res.json({ success: true, message: `Landlord ${action}d` });
    }
  );
});

// =========================
// M-PESA
// =========================
const axios = require("axios");

async function getMpesaToken() {
  const key    = process.env.MPESA_CONSUMER_KEY;
  const secret = process.env.MPESA_CONSUMER_SECRET;
  const credentials = Buffer.from(`${key}:${secret}`).toString("base64");

  const { data } = await axios.get(
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: `Basic ${credentials}` } }
  );

  return data.access_token;
}

function getMpesaPassword(timestamp) {
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey   = process.env.MPESA_PASSKEY;
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString("base64");
}

function getTimestamp() {
  return new Date()
    .toLocaleString("en-KE", { timeZone: "Africa/Nairobi" })
    .replace(/[^0-9]/g, "")
    .replace(/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/, "20$3$2$1$4$5$6");
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

    const payload = {
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
      TransactionDesc:   description || "Property listing fee"
    };

    const { data } = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      payload,
      { headers: { Authorization: `Bearer ${token}` } }
    );

    if (data.ResponseCode !== "0") {
      return res.status(400).json({
        success: false,
        message: data.ResponseDescription || "STK push failed"
      });
    }

    const sql = `
      INSERT INTO mpesa_payments
        (checkout_request_id, landlord_id, phone, amount, status, created_at)
      VALUES (?, ?, ?, ?, 'pending', NOW())
    `;
    db.query(sql, [data.CheckoutRequestID, req.user.id, phone, amount], (err) => {
      if (err) console.error("DB insert mpesa_payments:", err.message);
    });

    return res.json({
      success:           true,
      CheckoutRequestID: data.CheckoutRequestID,
      message:           "STK push sent successfully"
    });

  } catch (err) {
    console.error("STK push error:", err.response?.data || err.message);
    return res.status(500).json({
      success: false,
      message: "Could not initiate M-Pesa payment. Try again."
    });
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
      const receipt = items.find(i => i.Name === "MpesaReceiptNumber")?.Value || null;
      const amount  = items.find(i => i.Name === "Amount")?.Value || null;
      const phone   = items.find(i => i.Name === "PhoneNumber")?.Value || null;

      const sql = `
        UPDATE mpesa_payments
        SET status = 'completed',
            transaction_id = ?,
            amount = COALESCE(?, amount),
            phone  = COALESCE(?, phone),
            paid_at = NOW()
        WHERE checkout_request_id = ?
      `;
      db.query(sql, [receipt, amount, phone, checkId], (err) => {
        if (err) console.error("Callback update (success):", err.message);
      });

    } else {
      const sql = `
        UPDATE mpesa_payments
        SET status = 'failed',
            result_desc = ?
        WHERE checkout_request_id = ?
      `;
      db.query(sql, [body?.ResultDesc || "Failed", checkId], (err) => {
        if (err) console.error("Callback update (fail):", err.message);
      });
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

  const sql = `
    SELECT status, transaction_id, result_desc
    FROM mpesa_payments
    WHERE checkout_request_id = ?
    LIMIT 1
  `;

  db.query(sql, [checkoutRequestId], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    if (rows.length === 0) {
      return res.json({ success: true, status: "pending" });
    }

    const { status, transaction_id, result_desc } = rows[0];

    return res.json({
      success:        true,
      status,
      transaction_id: transaction_id || null,
      message:        result_desc || null
    });
  });
});

// =========================
// UPLOAD PROPERTY (with M-Pesa verification)
// =========================
app.post("/upload-property", auth, upload.single("image"), (req, res) => {

  // Block tenants from listing properties
  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Only landlords can list properties." });
  }

  const {
    landlord_id, title, price, location,
    description, type, maps_url,
    mpesa_transaction_id, listing_expires_at
  } = req.body;

  if (!req.file) {
    return res.status(400).json({ success: false, message: "Image required" });
  }

  const verifySql = `
    SELECT id FROM mpesa_payments
    WHERE transaction_id = ?
      AND landlord_id    = ?
      AND status         = 'completed'
    LIMIT 1
  `;

  db.query(verifySql, [mpesa_transaction_id, landlord_id], (verifyErr, verifyRows) => {
    if (verifyErr) {
      return res.status(500).json({ success: false, message: verifyErr.message });
    }

    if (verifyRows.length === 0) {
      return res.status(402).json({
        success: false,
        message: "Payment not verified. Please complete M-Pesa payment first."
      });
    }

    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: "qejaconnect" },
      (err, result) => {
        if (err) {
          return res.status(500).json({ success: false, message: err.message });
        }

        const image_url = result.secure_url;

        const expiresAt = listing_expires_at
          ? new Date(listing_expires_at)
          : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

        const sql = `
          INSERT INTO properties
            (landlord_id, title, price, location, description,
             type, image_url, maps_url, listing_expires_at, mpesa_transaction_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        db.query(
          sql,
          [
            landlord_id, title, price, location, description,
            type, image_url, maps_url || null,
            expiresAt, mpesa_transaction_id
          ],
          (err2) => {
            if (err2) {
              return res.status(500).json({ success: false, message: err2.message });
            }

            db.query(
              `UPDATE mpesa_payments SET status = 'used' WHERE transaction_id = ?`,
              [mpesa_transaction_id]
            );

            res.json({ success: true, message: "Property uploaded", image_url });
          }
        );
      }
    );

    streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
  });
});

// =========================
// WEBAUTHN — FINGERPRINT LOGIN
// =========================
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const RP_NAME = 'QejaConnect';
const RP_ID   = 'eliyasande65-lang.github.io';
const ORIGIN  = 'https://eliyasande65-lang.github.io';

const challenges = new Map();

// ── Register Start ────────────────────────────────────────
app.post('/auth/webauthn/register/start', async (req, res) => {
  try {
    const { userId, userName, userEmail } = req.body;

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: new TextEncoder().encode(String(userId)),
      userName: userEmail,
      userDisplayName: userName,
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification: 'required',
        residentKey: 'preferred'
      },
    });

    challenges.set(String(userId), options.challenge);
    res.json(options);

  } catch (err) {
    console.error('WebAuthn register/start error:', err.message);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ── Register Finish ───────────────────────────────────────
app.post('/auth/webauthn/register/finish', async (req, res) => {
  try {
    const { userId, credential } = req.body;
    const entry = challenges.get(String(userId));

    if (!entry || Date.now() > entry.expires) {
      return res.status(400).json({ success: false, message: 'Challenge expired. Try again.' });
    }

    const expectedChallenge = entry.challenge;

    if (!expectedChallenge) {
      return res.status(400).json({ success: false, message: 'Challenge expired. Try again.' });
    }

    const { verified, registrationInfo } = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verified) {
      return res.status(400).json({ success: false, message: 'Verification failed' });
    }

    const sql = `
      INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
      VALUES (?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        credential_id = VALUES(credential_id),
        public_key    = VALUES(public_key),
        counter       = VALUES(counter)
    `;

    db.query(sql, [
      parseInt(userId),
      Buffer.from(registrationInfo.credential.id, 'base64url').toString('base64'),
      Buffer.from(registrationInfo.credential.publicKey),
      registrationInfo.credential.counter ?? 0
    ], (err) => {
      if (err) {
        console.error('WebAuthn DB save error:', err.message);
        return res.status(500).json({ success: false, message: err.message });
      }
      challenges.delete(String(userId));
      res.json({ success: true });
    });

  } catch (err) {
    console.error('WebAuthn register/finish error:', err.message);
    res.status(400).json({ success: false, message: err.message });
  }
});

// ── Login Start ───────────────────────────────────────────
app.post('/auth/webauthn/login/start', (req, res) => {
  const { userId } = req.body;

  db.query(
    'SELECT * FROM webauthn_credentials WHERE user_id = ?',
    [parseInt(userId)],
    async (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: 'No fingerprint registered for this user' });
      }

      const cred = rows[0];

      try {
        const credIdBase64url = Buffer.from(cred.credential_id, 'base64').toString('base64url');

        const options = await generateAuthenticationOptions({
          rpID: RP_ID,
          userVerification: 'required',
          allowCredentials: [{
            id: credIdBase64url,
            type: 'public-key',
          }],
        });

        challenges.set(String(userId), {
          challenge: options.challenge,
          expires: Date.now() + 5 * 60 * 1000
        });

      } catch (err2) {
        console.error('WebAuthn login/start error:', err2.message);
        res.status(500).json({ success: false, message: err2.message });
      }
    }
  );
});

// ── Login Finish ──────────────────────────────────────────
app.post('/auth/webauthn/login/finish', (req, res) => {
  const { userId, credential } = req.body;
  const entry = challenges.get(String(userId));

  if (!entry || Date.now() > entry.expires) {
    return res.status(400).json({ success: false, message: 'Challenge expired. Try again.' });
  }

  const expectedChallenge = entry.challenge;

  db.query(
    'SELECT * FROM webauthn_credentials WHERE user_id = ?',
    [parseInt(userId)],
    async (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      if (rows.length === 0) {
        return res.status(404).json({ success: false, message: 'Credential not found' });
      }

      const cred = rows[0];

      try {
        const { verified, authenticationInfo } = await verifyAuthenticationResponse({
          response: credential,
          expectedChallenge,
          expectedOrigin: ORIGIN,
          expectedRPID: RP_ID,
          authenticator: {
            credentialID: new Uint8Array(Buffer.from(cred.credential_id, 'base64')),
            credentialPublicKey: new Uint8Array(cred.public_key),
            counter: cred.counter
          }
        });

        if (!verified) {
          return res.status(401).json({ success: false, message: 'Fingerprint verification failed' });
        }

        db.query(
          'UPDATE webauthn_credentials SET counter = ? WHERE user_id = ?',
          [authenticationInfo.newCounter, parseInt(userId)]
        );

        challenges.delete(String(userId));

        db.query('SELECT * FROM users WHERE id = ?', [parseInt(userId)], (err2, users) => {
          if (err2) return res.status(500).json({ success: false, message: err2.message });

          if (users.length > 0) {
            const user = users[0];
            const token = jwt.sign(
              { id: user.id, role: 'tenant' },
              process.env.JWT_SECRET,
              { expiresIn: '1d' }
            );
            const { password: _pw, ...safeUser } = user;
            return res.json({ success: true, role: 'tenant', token, user: safeUser });
          }

          db.query('SELECT * FROM landlords WHERE id = ?', [parseInt(userId)], (err3, landlords) => {
            if (err3) return res.status(500).json({ success: false, message: err3.message });

            if (landlords.length === 0) {
              return res.status(404).json({ success: false, message: 'User not found' });
            }

            const landlord = landlords[0];
            const token = jwt.sign(
              { id: landlord.id, role: 'landlord' },
              process.env.JWT_SECRET,
              { expiresIn: '1d' }
            );
            const { password: _pw, ...safeLandlord } = landlord;
            res.json({ success: true, role: 'landlord', token, user: safeLandlord });
          });
        });

      } catch (err) {
        console.error('WebAuthn login/finish error:', err.message);
        res.status(400).json({ success: false, message: err.message });
      }
    }
  );
});

// =========================
// UPDATE PHONE (landlord only)
// =========================
app.patch("/update-phone", auth, (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ success: false, message: "Phone number required" });
  }

  if (req.user.role !== "landlord") {
    return res.status(403).json({ success: false, message: "Only landlords can update phone" });
  }

  db.query(
    "UPDATE landlords SET phone = ? WHERE id = ?",
    [phone, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      res.json({ success: true, message: "Phone updated" });
    }
  );
});

// =========================
// UPLOAD TENANT PROFILE PIC
// =========================
app.post("/upload-tenant-pic", auth, upload.single("image"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: "No image uploaded" });
  }

  if (req.user.role !== "tenant") {
    return res.status(403).json({ success: false, message: "Tenants only" });
  }

  const uploadStream = cloudinary.uploader.upload_stream(
    { folder: "qejaconnect_profiles" },
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: err.message });

      const imageUrl = result.secure_url;
      db.query(
        "UPDATE users SET profile_pic = ? WHERE id = ?",
        [imageUrl, req.user.id],
        (err2) => {
          if (err2) return res.status(500).json({ success: false, message: err2.message });
          res.json({ success: true, image: imageUrl });
        }
      );
    }
  );

  streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
});



// ============================================================
//  NEW ROUTE 1 — Admin: get all contact messages (paginated)
//  GET /admin/messages?page=1&limit=20&replied=0|1

// ============================================================
app.get("/admin/messages", adminAuth, (req, res) => {
  const page     = Math.max(1, parseInt(req.query.page)  || 1);
  const limit    = Math.min(100, parseInt(req.query.limit) || 20);
  const offset   = (page - 1) * limit;
  const replied  = req.query.replied; // '0' = unreplied, '1' = replied, undefined = all

  let where  = "";
  let params = [];

  if (replied === "0") {
    where  = "WHERE cm.reply IS NULL";
  } else if (replied === "1") {
    where  = "WHERE cm.reply IS NOT NULL";
  }

  const countSql = `SELECT COUNT(*) AS total FROM contact_messages cm ${where}`;

  const dataSql = `
    SELECT
      cm.id,
      cm.sender_id,
      cm.sender_role,
      cm.message,
      cm.reply,
      cm.replied_at,
      cm.created_at,
      CASE
        WHEN cm.sender_role = 'tenant'   THEN u.fullname
        WHEN cm.sender_role = 'landlord' THEN l.fullname
        ELSE 'Unknown'
      END AS sender_name,
      CASE
        WHEN cm.sender_role = 'tenant'   THEN u.email
        WHEN cm.sender_role = 'landlord' THEN l.email
        ELSE NULL
      END AS sender_email
    FROM contact_messages cm
    LEFT JOIN users     u ON cm.sender_role = 'tenant'   AND cm.sender_id = u.id
    LEFT JOIN landlords l ON cm.sender_role = 'landlord' AND cm.sender_id = l.id
    ${where}
    ORDER BY cm.created_at DESC
    LIMIT ? OFFSET ?
  `;

  db.query(countSql, params, (err, countRows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });

    const total = countRows[0].total;

    db.query(dataSql, [...params, limit, offset], (err2, rows) => {
      if (err2) return res.status(500).json({ success: false, message: err2.message });

      res.json({ success: true, total, page, limit, messages: rows });
    });
  });
});

// ============================================================
//  NEW ROUTE 2 — Admin: reply to a contact message
//  POST /admin/messages/:id/reply

//  Add this BEFORE "START SERVER"
// ============================================================
app.post("/admin/messages/:id/reply", adminAuth, (req, res) => {
  const { id }    = req.params;
  const { reply } = req.body;

  if (!reply || !reply.trim()) {
    return res.status(400).json({ success: false, message: "Reply text is required" });
  }

  db.query(
    `UPDATE contact_messages SET reply = ?, replied_at = NOW() WHERE id = ?`,
    [reply.trim(), id],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: "Message not found" });
      }
      res.json({ success: true, message: "Reply sent" });
    }
  );
});

// ============================================================
//  NEW ROUTE 3 — User: fetch their own messages + admin replies
//  GET /my-messages   (requires auth token)

// ============================================================
app.get("/my-messages", auth, (req, res) => {
  const sender_id   = req.user.id;
  const sender_role = req.user.role;

  const sql = `
    SELECT id, message, reply, replied_at, created_at
    FROM contact_messages
    WHERE sender_id = ? AND sender_role = ?
    ORDER BY created_at DESC
  `;

  db.query(sql, [sender_id, sender_role], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, messages: rows });
  });
});


db.query(
  "SELECT title, price, location, type FROM properties LIMIT 20",
  async (err, properties) => {

    const propertyText = properties
      .map(p =>
        `${p.title} | ${p.price} | ${p.location} | ${p.type}`
      )
      .join("\n");

    // Send propertyText into OpenAI prompt
});

// =========================
// QEJACONNECT AI
// =========================

app.post("/ai/chat", auth, async (req, res) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({ success: false, message: "Message required" });
    }

    // OPTIONAL: database search first
    let propertyText = "";

    if (message.toLowerCase().includes("juja")) {
      const [properties] = await db.promise().query(
        "SELECT title, price, location, type FROM properties WHERE location LIKE '%Juja%' LIMIT 20"
      );

      propertyText = properties
        .map(p => `${p.title} | ${p.price} | ${p.location} | ${p.type}`)
        .join("\n");
    }

    const response = await openai.responses.create({
      model: "gpt-4o-mini",
      input: [
        {
          role: "system",
          content: `
You are QejaConnect AI.

If property data is provided, use it:
${propertyText}
`
        },
        {
          role: "user",
          content: message
        }
      ]
    });

    res.json({
      success: true,
      reply: response.output_text
    });

  } catch (err) {
    console.error("AI error:", err);
    res.status(500).json({ success: false, message: "AI error" });
  }
});



//  multer + cloudinary are already imported in your server — no
//  new dependencies needed.
// =============================================================


// ── GET /updates  (public — home page uses this) ─────────────
app.get("/updates", (req, res) => {
  const sql = `
    SELECT id, title, body, type, image_url, cta_url, cta_label, created_at
    FROM updates
    ORDER BY created_at DESC
    LIMIT 50
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, updates: rows });
  });
});


// ── POST /admin/updates  (admin only — create an update) ─────
app.post("/admin/updates", adminAuth, upload.single("image"), async (req, res) => {
  const { title, body, type, cta_url, cta_label } = req.body;

  if (!title || !body) {
    return res.status(400).json({ success: false, message: "title and body are required" });
  }

  const validTypes = ["announcement", "maintenance", "alert", "feature", "promotion"];
  const updateType = validTypes.includes(type) ? type : "announcement";

  try {
    let image_url = null;

    // Upload image to Cloudinary if provided
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

    const sql = `
      INSERT INTO updates (title, body, type, image_url, cta_url, cta_label)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sql,
      [title.trim(), body.trim(), updateType, image_url, cta_url || null, cta_label || null],
      (err, result) => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        res.json({ success: true, message: "Update published", id: result.insertId });
      }
    );
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// ── DELETE /admin/updates/:id  (admin only) ──────────────────
app.delete("/admin/updates/:id", adminAuth, (req, res) => {
  const { id } = req.params;

  db.query("DELETE FROM updates WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: "Update not found" });
    }
    res.json({ success: true, message: "Update deleted" });
  });
});
// =========================
// START SERVER
// =========================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});
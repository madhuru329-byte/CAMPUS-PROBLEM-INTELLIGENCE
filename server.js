const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 4000;

// ============================================================
// APP CONFIG
// ============================================================

app.use(cors());
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "campus-problem-secret-2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

// ============================================================
// DATABASE
// ============================================================

const db = new Database("campus.db");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('student', 'department')),
  department TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  location TEXT,
  reporter_name TEXT,
  reporter_id TEXT,
  category TEXT NOT NULL,
  department TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  priority_score REAL DEFAULT 0,
  priority_level TEXT DEFAULT 'Medium',
  upvotes INTEGER DEFAULT 0,
  cluster_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS upvotes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  UNIQUE(report_id, user_id)
);

CREATE TABLE IF NOT EXISTS clusters (
  id TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  department TEXT NOT NULL,
  title TEXT NOT NULL,
  tokens TEXT NOT NULL,
  count INTEGER DEFAULT 1,
  status TEXT DEFAULT 'open',
  created_at TEXT NOT NULL
);
`);

// ============================================================
// DEPARTMENT KNOWLEDGE BASE
// ============================================================

const CATEGORY_RULES = [
  {
    category: "Electrical",
    department: "Electrical Maintenance",
    keywords: [
      "electric", "electricity", "wire", "wiring", "shock", "spark",
      "switchboard", "power cut", "socket", "short circuit", "bulb", "fan", "mcb", "light"
    ]
  },
  {
    category: "Plumbing",
    department: "Plumbing & Water Supply",
    keywords: [
      "water", "leak", "leakage", "tap", "pipe", "drain", "toilet",
      "flush", "sewage", "washroom", "bathroom", "overflow"
    ]
  },
  {
    category: "IT/WiFi",
    department: "IT Services",
    keywords: [
      "wifi", "wi-fi", "internet", "network", "lan", "server", "portal",
      "login", "password", "website", "app", "crash", "projector", "computer", "printer"
    ]
  },
  {
    category: "Cleanliness",
    department: "Housekeeping",
    keywords: [
      "dirty", "garbage", "trash", "litter", "clean", "dust", "smell",
      "waste", "unhygienic", "pest", "cockroach", "rat"
    ]
  },
  {
    category: "Security",
    department: "Campus Security",
    keywords: [
      "theft", "stolen", "unsafe", "harassment", "stranger", "gate",
      "guard", "cctv", "fight", "ragging", "fire alarm", "trespass"
    ]
  },
  {
    category: "Infrastructure",
    department: "Civil & Infrastructure",
    keywords: [
      "crack", "ceiling", "roof", "wall", "collapse", "pothole",
      "road", "floor", "staircase", "elevator", "lift", "construction"
    ]
  },
  {
    category: "Furniture",
    department: "Facilities Management",
    keywords: [
      "chair", "desk", "bench", "table", "broken furniture",
      "door", "window", "lock broken", "hinge"
    ]
  },
  {
    category: "Transport",
    department: "Transport Office",
    keywords: ["bus", "shuttle", "parking", "transport", "driver", "route", "delay"]
  },
  {
    category: "Hostel",
    department: "Hostel Administration",
    keywords: ["hostel", "room", "warden", "mess food", "mess", "roommate", "curfew"]
  }
];

const DEPARTMENTS = [
  "Electrical Maintenance",
  "Plumbing & Water Supply",
  "IT Services",
  "Housekeeping",
  "Campus Security",
  "Civil & Infrastructure",
  "Facilities Management",
  "Transport Office",
  "Hostel Administration",
  "General Administration"
];

const SEVERITY_KEYWORDS = {
  high: [
    "fire", "shock", "gas leak", "collapse", "injury", "unsafe",
    "harassment", "flood", "short circuit", "theft", "emergency", "ragging"
  ],
  medium: ["broken", "not working", "leak", "crack", "delay", "dirty", "pest", "slow"],
  low: ["dusty", "minor", "cosmetic"]
};

const STOPWORDS = new Set([
  "the", "is", "a", "an", "and", "or", "of", "in", "on", "at", "to",
  "for", "with", "this", "that", "it", "are", "was", "were", "be",
  "has", "have", "not", "no", "please", "fix", "there"
]);

// ============================================================
// HELPERS
// ============================================================

function now() {
  return new Date().toISOString();
}

function tokenize(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w && !STOPWORDS.has(w));
}

function classify(text) {
  const lower = text.toLowerCase();
  let best = {
    category: "Other",
    department: "General Administration",
    score: 0
  };

  for (const rule of CATEGORY_RULES) {
    let hits = 0;
    for (const keyword of rule.keywords) {
      if (lower.includes(keyword)) hits++;
    }
    if (hits > best.score) {
      best = {
        category: rule.category,
        department: rule.department,
        score: hits
      };
    }
  }

  return {
    category: best.category,
    department: best.department
  };
}

// Fixed: Increased high severity base score so emergencies immediately rank High/Critical
function severityScore(text) {
  const lower = text.toLowerCase();
  if (SEVERITY_KEYWORDS.high.some((k) => lower.includes(k))) return 12;
  if (SEVERITY_KEYWORDS.medium.some((k) => lower.includes(k))) return 6;
  if (SEVERITY_KEYWORDS.low.some((k) => lower.includes(k))) return 2;
  return 4;
}

function jaccard(aTokens, bTokens) {
  const a = new Set(aTokens);
  const b = new Set(bTokens);
  const intersection = [...a].filter((x) => b.has(x)).length;
  const union = new Set([...a, ...b]).size;
  return union === 0 ? 0 : intersection / union;
}

function calculatePriority(report, clusterCount) {
  const severity = severityScore(report.title + " " + report.description);
  const frequencyWeight = Math.min(clusterCount * 2, 10);
  const ageDays = Math.max(0, (Date.now() - new Date(report.created_at)) / 86400000);
  const ageWeight = Math.min(ageDays * 0.5, 10);
  const upvoteWeight = Math.min((report.upvotes || 0) * 1.5, 8);

  const score = severity + frequencyWeight + ageWeight + upvoteWeight;

  let level = "Low";
  if (score >= 18) {
    level = "Critical";
  } else if (score >= 12) {
    level = "High";
  } else if (score >= 6) {
    level = "Medium";
  }

  return {
    score: Math.round(score * 10) / 10,
    level
  };
}

// Fixed: Reopens resolved cluster and preserves token balance
function findCluster(report) {
  const reportTokens = tokenize(report.title + " " + report.description);
  const allClusters = db.prepare("SELECT * FROM clusters").all();

  let bestCluster = null;
  let bestSimilarity = 0;

  for (const cluster of allClusters) {
    if (cluster.category !== report.category) continue;
    const clusterTokens = JSON.parse(cluster.tokens);
    const similarity = jaccard(reportTokens, clusterTokens);

    if (similarity > bestSimilarity) {
      bestSimilarity = similarity;
      bestCluster = cluster;
    }
  }

  const SIMILARITY_THRESHOLD = 0.25;

  if (bestCluster && bestSimilarity >= SIMILARITY_THRESHOLD) {
    db.prepare(`
      UPDATE clusters
      SET count = count + 1,
          status = 'open'
      WHERE id = ?
    `).run(bestCluster.id);

    return {
      id: bestCluster.id,
      count: bestCluster.count + 1,
      duplicate: true
    };
  }

  const clusterId = crypto.randomUUID();
  db.prepare(`
    INSERT INTO clusters
    (id, category, department, title, tokens, count, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    clusterId,
    report.category,
    report.department,
    report.title,
    JSON.stringify(reportTokens),
    1,
    "open",
    now()
  );

  return {
    id: clusterId,
    count: 1,
    duplicate: false
  };
}

function getReportForResponse(r, currentUserId) {
  let hasUpvoted = false;
  if (currentUserId) {
    const up = db.prepare("SELECT id FROM upvotes WHERE report_id = ? AND user_id = ?").get(r.id, currentUserId);
    hasUpvoted = Boolean(up);
  }

  return {
    id: r.id,
    title: r.title,
    description: r.description,
    location: r.location,
    reporterName: r.reporter_name,
    isOwner: currentUserId === r.reporter_id,
    category: r.category,
    department: r.department,
    status: r.status,
    priorityScore: r.priority_score,
    priorityLevel: r.priority_level,
    upvotes: r.upvotes,
    hasUpvoted,
    clusterId: r.cluster_id,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    resolvedAt: r.resolved_at
  };
}

function refreshPriorities() {
  const reports = db.prepare("SELECT * FROM reports").all();
  const getCluster = db.prepare("SELECT count FROM clusters WHERE id = ?");
  const update = db.prepare(`
    UPDATE reports
    SET priority_score = ?,
        priority_level = ?
    WHERE id = ?
  `);

  const transaction = db.transaction(() => {
    for (const report of reports) {
      if (report.status === "resolved") continue;
      const cluster = report.cluster_id ? getCluster.get(report.cluster_id) : null;
      const priority = calculatePriority(report, cluster ? cluster.count : 1);
      update.run(priority.score, priority.level, report.id);
    }
  });

  transaction();
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: "Please login first" });
  }
  next();
}

function requireStudent(req, res, next) {
  if (!req.session.user || req.session.user.role !== "student") {
    return res.status(403).json({ error: "Student access required" });
  }
  next();
}

function requireDepartment(req, res, next) {
  if (!req.session.user || req.session.user.role !== "department") {
    return res.status(403).json({ error: "Department access required" });
  }
  next();
}

// ============================================================
// CREATE DEFAULT USERS
// ============================================================

function createDefaultUsers() {
  const studentExists = db.prepare("SELECT id FROM users WHERE username = ?").get("student");
  if (!studentExists) {
    const password = bcrypt.hashSync("student123", 10);
    db.prepare(`
      INSERT INTO users (id, name, username, password, role, department, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), "Demo Student", "student", password, "student", null, now());
  }

  const departmentUsers = [
    { name: "IT Department", username: "it", department: "IT Services" },
    { name: "Electrical Department", username: "electrical", department: "Electrical Maintenance" },
    { name: "Plumbing Department", username: "plumbing", department: "Plumbing & Water Supply" },
    { name: "Housekeeping Department", username: "housekeeping", department: "Housekeeping" },
    { name: "Security Department", username: "security", department: "Campus Security" },
    { name: "Civil Department", username: "civil", department: "Civil & Infrastructure" },
    { name: "Facilities Department", username: "facilities", department: "Facilities Management" },
    { name: "Transport Department", username: "transport", department: "Transport Office" },
    { name: "Hostel Department", username: "hostel", department: "Hostel Administration" }
  ];

  for (const d of departmentUsers) {
    const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(d.username);
    if (!exists) {
      const password = bcrypt.hashSync("admin123", 10);
      db.prepare(`
        INSERT INTO users (id, name, username, password, role, department, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(crypto.randomUUID(), d.name, d.username, password, "department", d.department, now());
    }
  }
}

createDefaultUsers();

// ============================================================
// AUTH ROUTES
// ============================================================

// Added: Student sign-up route
app.post("/api/auth/register", (req, res) => {
  const { name, username, password } = req.body;
  if (!name || !username || !password) {
    return res.status(400).json({ error: "Name, username, and password are required" });
  }

  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username.trim());
  if (exists) {
    return res.status(400).json({ error: "Username already taken" });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const userId = crypto.randomUUID();

  db.prepare(`
    INSERT INTO users (id, name, username, password, role, department, created_at)
    VALUES (?, ?, ?, ?, 'student', null, ?)
  `).run(userId, name.trim(), username.trim(), hashedPassword, now());

  req.session.user = {
    id: userId,
    name: name.trim(),
    username: username.trim(),
    role: "student",
    department: null
  };

  res.status(201).json({ message: "Registration successful", user: req.session.user });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password, loginType } = req.body;
  if (!username || !password || !loginType) {
    return res.status(400).json({ error: "Username, password and login type are required" });
  }

  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user || user.role !== loginType) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  req.session.user = {
    id: user.id,
    name: user.name,
    username: user.username,
    role: user.role,
    department: user.department
  };

  res.json({ message: "Login successful", user: req.session.user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ message: "Logged out" });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  res.json(req.session.user);
});

// ============================================================
// STUDENT: CREATE REPORT
// ============================================================

app.post("/api/reports", requireStudent, (req, res) => {
  const { title, description, location, anonymous } = req.body;
  if (!title || !description) {
    return res.status(400).json({ error: "Title and description are required" });
  }

  const combinedText = title + " " + description;
  const { category, department } = classify(combinedText);

  const report = {
    id: crypto.randomUUID(),
    title: title.trim(),
    description: description.trim(),
    location: location?.trim() || "Unspecified",
    reporter_name: anonymous ? "Anonymous Student" : req.session.user.name,
    reporter_id: req.session.user.id,
    category,
    department,
    status: "open",
    upvotes: 0,
    created_at: now(),
    updated_at: now()
  };

  const cluster = findCluster(report);
  const priority = calculatePriority(report, cluster.count);

  db.prepare(`
    INSERT INTO reports
    (id, title, description, location, reporter_name, reporter_id, category, department, status, priority_score, priority_level, upvotes, cluster_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    report.id, report.title, report.description, report.location,
    report.reporter_name, report.reporter_id, report.category, report.department,
    "open", priority.score, priority.level, 0, cluster.id, report.created_at, report.updated_at
  );

  res.status(201).json({
    report: getReportForResponse(
      { ...report, priority_score: priority.score, priority_level: priority.level, cluster_id: cluster.id, resolved_at: null },
      req.session.user.id
    ),
    isDuplicateOfExisting: cluster.duplicate,
    clusterCount: cluster.count
  });
});

// ============================================================
// REPORTS LIST (Fixed: Community Feed & Mine Scoping)
// ============================================================

app.get("/api/reports", requireLogin, (req, res) => {
  refreshPriorities();

  const { status, department, category, sort, scope } = req.query;
  let query = "SELECT * FROM reports";
  const conditions = [];
  const params = [];

  if (status) {
    conditions.push("status = ?");
    params.push(status);
  }

  if (department) {
    conditions.push("department = ?");
    params.push(department);
  }

  if (category) {
    conditions.push("category = ?");
    params.push(category);
  }

  // Department users view tickets assigned to their department
  if (req.session.user.role === "department") {
    conditions.push("department = ?");
    params.push(req.session.user.department);
  }

  // Students can view "mine" or campus-wide "all"
  if (req.session.user.role === "student" && scope === "mine") {
    conditions.push("reporter_id = ?");
    params.push(req.session.user.id);
  }

  if (conditions.length) {
    query += " WHERE " + conditions.join(" AND ");
  }

  if (sort === "priority") {
    query += " ORDER BY priority_score DESC, datetime(created_at) DESC";
  } else {
    query += " ORDER BY datetime(created_at) DESC";
  }

  const rows = db.prepare(query).all(...params);
  res.json(rows.map((r) => getReportForResponse(r, req.session.user.id)));
});

app.get("/api/reports/:id", requireLogin, (req, res) => {
  const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(req.params.id);
  if (!report) {
    return res.status(404).json({ error: "Report not found" });
  }

  if (req.session.user.role === "department" && report.department !== req.session.user.department) {
    return res.status(403).json({ error: "Access denied" });
  }

  res.json(getReportForResponse(report, req.session.user.id));
});

// ============================================================
// DEPARTMENT UPDATE STATUS
// ============================================================

app.patch("/api/reports/:id", requireDepartment, (req, res) => {
  const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(req.params.id);
  if (!report) {
    return res.status(404).json({ error: "Report not found" });
  }

  if (report.department !== req.session.user.department) {
    return res.status(403).json({ error: "You can only update problems assigned to your department" });
  }

  const { status } = req.body;
  if (!["open", "in-progress", "resolved"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const resolvedAt = status === "resolved" ? now() : null;

  db.prepare(`
    UPDATE reports
    SET status = ?,
        updated_at = ?,
        resolved_at = ?
    WHERE id = ?
  `).run(status, now(), resolvedAt, report.id);

  // Update cluster status
  if (report.cluster_id) {
    const clusterReports = db.prepare("SELECT status FROM reports WHERE cluster_id = ?").all(report.cluster_id);
    const allResolved = clusterReports.length > 0 && clusterReports.every((r) => r.status === "resolved");

    db.prepare("UPDATE clusters SET status = ? WHERE id = ?").run(allResolved ? "resolved" : "open", report.cluster_id);
  }

  const updated = db.prepare("SELECT * FROM reports WHERE id = ?").get(report.id);
  res.json(getReportForResponse(updated, req.session.user.id));
});

// ============================================================
// UPVOTE (Fixed: Clean Toggle without Crash)
// ============================================================

app.post("/api/reports/:id/upvote", requireStudent, (req, res) => {
  const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(req.params.id);
  if (!report) {
    return res.status(404).json({ error: "Report not found" });
  }

  const existing = db.prepare("SELECT id FROM upvotes WHERE report_id = ? AND user_id = ?").get(report.id, req.session.user.id);

  if (existing) {
    // Toggle off: remove upvote
    db.prepare("DELETE FROM upvotes WHERE id = ?").run(existing.id);
    db.prepare("UPDATE reports SET upvotes = MAX(0, upvotes - 1), updated_at = ? WHERE id = ?").run(now(), report.id);
  } else {
    // Toggle on: add upvote
    db.prepare("INSERT INTO upvotes (report_id, user_id) VALUES (?, ?)").run(report.id, req.session.user.id);
    db.prepare("UPDATE reports SET upvotes = upvotes + 1, updated_at = ? WHERE id = ?").run(now(), report.id);
  }

  refreshPriorities();
  const updated = db.prepare("SELECT * FROM reports WHERE id = ?").get(report.id);
  res.json(getReportForResponse(updated, req.session.user.id));
});

// ============================================================
// ANALYTICS SUMMARY
// ============================================================

app.get("/api/analytics/summary", requireLogin, (req, res) => {
  refreshPriorities();

  let reports;
  if (req.session.user.role === "department") {
    reports = db.prepare("SELECT * FROM reports WHERE department = ?").all(req.session.user.department);
  } else {
    // Campus-wide stats for students
    reports = db.prepare("SELECT * FROM reports").all();
  }

  const byDepartment = {};
  const byStatus = { open: 0, "in-progress": 0, resolved: 0 };
  const byPriority = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const byCategory = {};
  const resolutionTimes = [];

  for (const r of reports) {
    byDepartment[r.department] = (byDepartment[r.department] || 0) + 1;
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    byPriority[r.priority_level] = (byPriority[r.priority_level] || 0) + 1;
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;

    if (r.status === "resolved" && r.resolved_at) {
      resolutionTimes.push((new Date(r.resolved_at) - new Date(r.created_at)) / 3600000);
    }
  }

  const avgResolutionHours = resolutionTimes.length
    ? Math.round(resolutionTimes.reduce((a, b) => a + b, 0) / resolutionTimes.length)
    : null;

  res.json({
    totalReports: reports.length,
    byDepartment,
    byStatus,
    byPriority,
    byCategory,
    avgResolutionHours
  });
});

// ============================================================
// TRENDING ISSUES (Fixed: Displays Campus Hotspots)
// ============================================================

app.get("/api/analytics/trending", requireLogin, (req, res) => {
  let query = "SELECT * FROM clusters WHERE status != 'resolved'";
  const params = [];

  if (req.session.user.role === "department") {
    query += " AND department = ?";
    params.push(req.session.user.department);
  }

  query += " ORDER BY count DESC LIMIT 10";
  const clusters = db.prepare(query).all(...params);

  const result = clusters.map((cluster) => {
    const locations = db
      .prepare("SELECT DISTINCT location FROM reports WHERE cluster_id = ?")
      .all(cluster.id)
      .map((x) => x.location);

    return {
      id: cluster.id,
      title: cluster.title,
      category: cluster.category,
      department: cluster.department,
      count: cluster.count,
      status: cluster.status,
      locations
    };
  });

  res.json(result);
});

// ============================================================
// FRONTEND
// ============================================================

const HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Campus Problem Intelligence</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
:root {
  --bg:#080d18;
  --card:#111827;
  --card2:#0d1422;
  --border:#243149;
  --text:#edf2ff;
  --muted:#8d99b5;
  --accent:#5b8cff;
  --green:#45d39c;
  --red:#ff5572;
  --orange:#ffad4a;
  --yellow:#f5d35b;
}
* { box-sizing:border-box; }
body {
  margin:0;
  font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:radial-gradient(circle at top right, #172554, transparent 35%), var(--bg);
  color:var(--text);
}
button, input, textarea, select { font:inherit; }
button { cursor:pointer; }
.hidden { display:none !important; }

#loginScreen {
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
}
.login-box {
  width:100%;
  max-width:440px;
  background:rgba(17,24,39,.96);
  border:1px solid var(--border);
  border-radius:20px;
  padding:28px;
  box-shadow:0 20px 60px rgba(0,0,0,.35);
}
.logo { text-align:center; font-size:38px; }
.login-box h1 { text-align:center; margin:8px 0; }
.login-box p { text-align:center; color:var(--muted); }
.login-tabs {
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:8px;
  margin:20px 0;
}
.login-tabs button {
  padding:11px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--card2);
  color:var(--muted);
}
.login-tabs button.active { background:var(--accent); color:white; }
.form-group { margin-bottom:14px; }
.form-group label { display:block; margin-bottom:6px; font-size:13px; color:var(--muted); }
input, textarea, select {
  width:100%;
  background:#080e1a;
  color:var(--text);
  border:1px solid var(--border);
  border-radius:9px;
  padding:11px;
  outline:none;
}
input:focus, textarea:focus, select:focus { border-color:var(--accent); }
.primary { background:var(--accent); color:white; border:0; border-radius:9px; padding:10px 16px; font-weight:600; }
.secondary { background:transparent; color:var(--text); border:1px solid var(--border); border-radius:9px; padding:9px 14px; }
.full { width:100%; }
.login-error { color:#ff7188; text-align:center; margin-top:12px; font-size:14px; }

header {
  position:sticky; top:0; z-index:10;
  background:rgba(8,13,24,.94);
  backdrop-filter:blur(14px);
  border-bottom:1px solid var(--border);
  padding:15px 22px;
}
.header-inner {
  max-width:1200px;
  margin:auto;
  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:15px;
}
.brand { display:flex; gap:10px; align-items:center; }
.brand-icon { font-size:30px; }
.brand h1 { font-size:18px; margin:0; }
.brand small { color:var(--muted); }
.user-area { display:flex; align-items:center; gap:10px; }
.role-badge { padding:5px 9px; border-radius:20px; background:#18243b; color:#9fbaff; font-size:12px; }

main { max-width:1200px; margin:auto; padding:25px 18px 60px; }
.card { background:rgba(17,24,39,.94); border:1px solid var(--border); border-radius:16px; padding:18px; margin-bottom:18px; }
.card h2 { margin:0 0 15px; font-size:15px; color:#c9d3e9; }
.dashboard-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
.stat { background:#0b1220; border:1px solid var(--border); border-radius:12px; padding:16px; }
.stat-number { font-size:26px; font-weight:700; }
.stat-label { color:var(--muted); font-size:12px; margin-top:4px; }
.content-grid { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
.chart-container { height:260px; position:relative; }

.report { background:#0b1220; border:1px solid var(--border); border-radius:12px; padding:14px; margin-bottom:10px; }
.report-title { font-weight:650; font-size:15px; }
.report-description { color:#aeb8ce; margin:8px 0; font-size:13px; line-height:1.5; white-space:pre-line; }
.meta { color:var(--muted); font-size:12px; line-height:1.8; }
.report-actions { display:flex; justify-content:space-between; align-items:center; gap:8px; margin-top:10px; flex-wrap:wrap; }

.priority { display:inline-block; padding:4px 9px; border-radius:20px; font-size:11px; font-weight:700; }
.priority-Critical { background:#ff5572; color:white; }
.priority-High { background:#ffad4a; color:#261900; }
.priority-Medium { background:#f5d35b; color:#201d00; }
.priority-Low { background:#45d39c; color:#00261b; }
.status { padding:4px 9px; border-radius:20px; background:#172237; font-size:11px; }

.trending-item { padding:13px 0; border-bottom:1px solid var(--border); }
.trending-item:last-child { border-bottom:0; }
.trending-count { float:right; color:#8fb1ff; font-weight:700; }
.empty { color:var(--muted); padding:15px 0; text-align:center; }
.success { color:var(--green); font-size:13px; margin-top:10px; }
.filters { display:flex; gap:8px; flex-wrap:wrap; margin-bottom:15px; }
.filters select { width:auto; min-width:140px; }
textarea { resize:vertical; }
.user-welcome { color:var(--muted); font-size:13px; }

@media(max-width:800px) {
  .dashboard-grid { grid-template-columns:1fr 1fr; }
  .content-grid { grid-template-columns:1fr; }
}
</style>
</head>
<body>

<!-- LOGIN SCREEN -->
<section id="loginScreen">
  <div class="login-box">
    <div class="logo">🎓</div>
    <h1>Campus Intelligence</h1>
    <p>Smart Campus Problem Management</p>

    <div class="login-tabs">
      <button id="studentTab" class="active" onclick="selectLoginType('student')">👨‍🎓 Student</button>
      <button id="departmentTab" onclick="selectLoginType('department')">🏢 Department</button>
    </div>

    <form id="loginForm">
      <div class="form-group" id="nameGroup" style="display:none;">
        <label>Full Name</label>
        <input id="loginName" placeholder="Enter your full name">
      </div>
      <div class="form-group">
        <label>Username</label>
        <input id="loginUsername" placeholder="Enter username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input id="loginPassword" type="password" placeholder="Enter password" required>
      </div>
      <button class="primary full" id="submitBtn">Login</button>
    </form>

    <div style="text-align:center; margin-top:12px;">
      <a href="#" id="toggleRegisterLink" style="color:var(--accent); font-size:13px; text-decoration:none;" onclick="toggleRegisterMode(event)">
        New Student? Register account
      </a>
    </div>

    <div id="loginError" class="login-error"></div>

    <div style="margin-top:20px; padding:12px; background:#0b1220; border-radius:10px; font-size:12px; color:#8995b0;">
      <strong>Demo Accounts</strong><br>
      Student: <b>student</b> / <b>student123</b><br>
      Department: <b>it</b> / <b>admin123</b>
    </div>
  </div>
</section>

<!-- MAIN APP -->
<div id="app" class="hidden">
  <header>
    <div class="header-inner">
      <div class="brand">
        <div class="brand-icon">🎓</div>
        <div>
          <h1>Campus Problem Intelligence</h1>
          <small>Automated NLP triage & resolution</small>
        </div>
      </div>
      <div class="user-area">
        <div>
          <div id="userName"></div>
          <span id="roleBadge" class="role-badge"></span>
        </div>
        <button class="secondary" onclick="logout()">Logout</button>
      </div>
    </div>
  </header>

  <main>
    <section class="card">
      <h2>📊 Campus Health Overview</h2>
      <div class="dashboard-grid" id="stats"></div>
    </section>

    <div class="content-grid">
      <section class="card">
        <h2>🎯 Problems by Priority</h2>
        <div class="chart-container">
          <canvas id="priorityChart"></canvas>
        </div>
      </section>

      <section class="card">
        <h2>🔥 Recurring Hotspots</h2>
        <div id="trending"></div>
      </section>
    </div>

    <!-- STUDENT REPORT FORM -->
    <section id="studentReportSection" class="card">
      <h2>📝 Report a Problem</h2>
      <form id="reportForm">
        <div class="form-group">
          <label>Problem Title</label>
          <input id="title" placeholder="Example: Water pipe burst in 2nd floor restroom" required>
        </div>
        <div class="form-group">
          <label>Detailed Description</label>
          <textarea id="description" rows="4" placeholder="Describe the issue. High severity words like 'leak', 'fire', 'shock' boost priority automatically." required></textarea>
        </div>
        <div class="form-group">
          <label>Location</label>
          <input id="location" placeholder="Example: Science Block A, Room 204">
        </div>
        <label style="display:flex; gap:8px; align-items:center; font-size:13px; color:var(--muted); margin-bottom:12px;">
          <input type="checkbox" id="anonymous" style="width:auto"> Submit anonymously
        </label>
        <button class="primary">Submit Ticket</button>
        <div id="submitResult"></div>
      </form>
    </section>

    <!-- REPORTS FEED -->
    <section class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:10px; flex-wrap:wrap;">
        <h2 id="reportsHeading">📋 Campus Problems Feed</h2>
        <div class="filters">
          <select id="filterScope" onchange="loadReports()">
            <option value="all">🌐 All Campus Issues</option>
            <option value="mine">👤 My Reports Only</option>
          </select>
          <select id="filterStatus" onchange="loadReports()">
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="in-progress">In Progress</option>
            <option value="resolved">Resolved</option>
          </select>
          <select id="sortBy" onchange="loadReports()">
            <option value="priority">Sort: Highest Priority</option>
            <option value="newest">Sort: Newest</option>
          </select>
          <button class="secondary" onclick="loadReports()">Refresh</button>
        </div>
      </div>
      <div id="reportsList"></div>
    </section>
  </main>
</div>

<script>
const API = "";
let currentUser = null;
let loginType = "student";
let isRegisterMode = false;
let priorityChart = null;

function selectLoginType(type) {
  loginType = type;
  document.getElementById("studentTab").classList.toggle("active", type === "student");
  document.getElementById("departmentTab").classList.toggle("active", type === "department");
  document.getElementById("loginError").textContent = "";

  const toggleLink = document.getElementById("toggleRegisterLink");
  if (type === "department") {
    isRegisterMode = false;
    document.getElementById("nameGroup").style.display = "none";
    document.getElementById("submitBtn").textContent = "Login";
    toggleLink.style.display = "none";
  } else {
    toggleLink.style.display = "inline";
  }
}

function toggleRegisterMode(e) {
  e.preventDefault();
  isRegisterMode = !isRegisterMode;
  document.getElementById("nameGroup").style.display = isRegisterMode ? "block" : "none";
  document.getElementById("submitBtn").textContent = isRegisterMode ? "Create Account" : "Login";
  document.getElementById("toggleRegisterLink").textContent = isRegisterMode ? "Already have an account? Login" : "New Student? Register account";
}

document.getElementById("loginForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  const error = document.getElementById("loginError");

  const endpoint = isRegisterMode ? "/api/auth/register" : "/api/auth/login";
  const payload = { username, password, loginType };
  if (isRegisterMode) payload.name = document.getElementById("loginName").value.trim();

  try {
    const response = await fetch(API + endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    if (!response.ok) {
      error.textContent = data.error || "Authentication failed";
      return;
    }
    currentUser = data.user;
    showApp();
  } catch(err) {
    error.textContent = "Server is not running or unreachable.";
  }
});

function showApp() {
  document.getElementById("loginScreen").classList.add("hidden");
  document.getElementById("app").classList.remove("hidden");

  document.getElementById("userName").innerHTML = '<div class="user-welcome">' + escapeHtml(currentUser.name) + '</div>';
  document.getElementById("roleBadge").innerHTML = currentUser.role === "student" ? "👨‍🎓 Student" : "🏢 " + escapeHtml(currentUser.department);

  const studentSection = document.getElementById("studentReportSection");
  const scopeFilter = document.getElementById("filterScope");

  if (currentUser.role === "student") {
    studentSection.classList.remove("hidden");
    scopeFilter.classList.remove("hidden");
  } else {
    studentSection.classList.add("hidden");
    scopeFilter.classList.add("hidden");
  }

  loadDashboard();
}

async function logout() {
  await fetch(API + "/api/auth/logout", { method: "POST" });
  location.reload();
}

async function loadDashboard() {
  await Promise.all([loadStats(), loadTrending(), loadReports()]);
}

async function loadStats() {
  const response = await fetch(API + "/api/analytics/summary");
  if (!response.ok) return;
  const s = await response.json();

  document.getElementById("stats").innerHTML = \`
    <div class="stat"><div class="stat-number">\${s.totalReports}</div><div class="stat-label">Total Tickets</div></div>
    <div class="stat"><div class="stat-number" style="color:var(--yellow)">\${s.byStatus.open}</div><div class="stat-label">Open</div></div>
    <div class="stat"><div class="stat-number" style="color:var(--green)">\${s.byStatus.resolved}</div><div class="stat-label">Resolved</div></div>
    <div class="stat"><div class="stat-number">\${s.avgResolutionHours ?? "—"} hrs</div><div class="stat-label">Avg Resolution Time</div></div>
  \`;

  createPriorityChart(s.byPriority);
}

// Fixed: Priority chart colors configured cleanly
function createPriorityChart(data) {
  const canvas = document.getElementById("priorityChart");
  if (priorityChart) priorityChart.destroy();

  priorityChart = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [data.Critical || 0, data.High || 0, data.Medium || 0, data.Low || 0],
        backgroundColor: ["#ff5572", "#ffad4a", "#f5d35b", "#45d39c"],
        borderColor: "#111827",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom", labels: { color: "#dce4f5" } }
      }
    }
  });
}

async function loadTrending() {
  const response = await fetch(API + "/api/analytics/trending");
  if (!response.ok) return;
  const clusters = await response.json();
  const el = document.getElementById("trending");

  if (!clusters.length) {
    el.innerHTML = '<div class="empty">No recurring hotspots detected.</div>';
    return;
  }

  el.innerHTML = clusters.map(c => \`
    <div class="trending-item">
      <span class="trending-count">\${c.count} Reports</span>
      <strong>\${escapeHtml(c.title)}</strong>
      <div class="meta">
        \${escapeHtml(c.department)} · \${escapeHtml(c.category)}<br>
        📍 \${c.locations.map(escapeHtml).join(", ")}
      </div>
    </div>
  \`).join("");
}

async function loadReports() {
  const status = document.getElementById("filterStatus").value;
  const sort = document.getElementById("sortBy").value;
  const scope = document.getElementById("filterScope").value;

  const params = new URLSearchParams({ sort });
  if (status) params.set("status", status);
  if (scope) params.set("scope", scope);

  const response = await fetch(API + "/api/reports?" + params.toString());
  if (!response.ok) return;
  const reports = await response.json();
  const el = document.getElementById("reportsList");

  if (!reports.length) {
    el.innerHTML = '<div class="empty">No complaints found.</div>';
    return;
  }
  el.innerHTML = reports.map(renderReport).join("");
}

// Fixed: Dropdown retains correct status; upvote button reflects active status
function renderReport(r) {
  let actions = "";
  if (currentUser.role === "student") {
    actions = \`
      <button class="\${r.hasUpvoted ? 'primary' : 'secondary'}" onclick="upvote('\${r.id}')">
        \${r.hasUpvoted ? '👍 Marked' : '👍 Me Too'} (\${r.upvotes})
      </button>
    \`;
  } else {
    actions = \`
      <select onchange="updateStatus('\${r.id}', this.value)">
        <option value="open" \${r.status === 'open' ? 'selected' : ''}>🟡 Open</option>
        <option value="in-progress" \${r.status === 'in-progress' ? 'selected' : ''}>🔄 In Progress</option>
        <option value="resolved" \${r.status === 'resolved' ? 'selected' : ''}>✅ Resolved</option>
      </select>
    \`;
  }

  return \`
    <div class="report">
      <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start; flex-wrap:wrap;">
        <div class="report-title">\${escapeHtml(r.title)}</div>
        <span class="priority priority-\${r.priorityLevel}">\${r.priorityLevel} (\${r.priorityScore})</span>
      </div>
      <div class="report-description">\${escapeHtml(r.description)}</div>
      <div class="meta">
        🏷️ \${escapeHtml(r.category)} · 🏢 \${escapeHtml(r.department)}<br>
        📍 \${escapeHtml(r.location)}<br>
        👤 \${escapeHtml(r.reporterName)} · 🕐 \${new Date(r.createdAt).toLocaleString()}
      </div>
      <div class="report-actions">
        <span class="status">\${r.status === 'in-progress' ? '🔄 In Progress' : r.status === 'resolved' ? '✅ Resolved' : '🟡 Open'}</span>
        <div style="display:flex; gap:7px; align-items:center;">\${actions}</div>
      </div>
    </div>
  \`;
}

document.getElementById("reportForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  const payload = {
    title: document.getElementById("title").value,
    description: document.getElementById("description").value,
    location: document.getElementById("location").value,
    anonymous: document.getElementById("anonymous").checked
  };

  const response = await fetch(API + "/api/reports", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  const result = document.getElementById("submitResult");

  if (!response.ok) {
    result.className = "login-error";
    result.textContent = data.error;
    return;
  }

  result.className = "success";
  result.innerHTML = \`
    ✅ Problem submitted successfully.<br>
    🏢 Routed to: <strong>\${escapeHtml(data.report.department)}</strong><br>
    🎯 Calculated Priority: <strong>\${data.report.priorityLevel} (\${data.report.priorityScore})</strong><br>
    \${data.isDuplicateOfExisting ? '♻️ Matches recurring campus hotspot. Total reports: ' + data.clusterCount : '🆕 New issue recorded.'}
  \`;
  e.target.reset();
  loadDashboard();
});

async function upvote(id) {
  const response = await fetch(API + "/api/reports/" + id + "/upvote", { method: "POST" });
  if (!response.ok) {
    const data = await response.json();
    alert(data.error);
    return;
  }
  loadDashboard();
}

async function updateStatus(id, status) {
  if (!status) return;
  const response = await fetch(API + "/api/reports/" + id, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status })
  });
  if (!response.ok) {
    const data = await response.json();
    alert(data.error);
    return;
  }
  loadDashboard();
}

function escapeHtml(val) {
  return String(val ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function checkLogin() {
  try {
    const response = await fetch(API + "/api/auth/me");
    if (!response.ok) return;
    currentUser = await response.json();
    showApp();
  } catch(e) {}
}

checkLogin();
</script>
</body>
</html>
`;

app.get("/", (req, res) => {
  res.send(HTML);
});

// ============================================================
// SERVER
// ============================================================

app.listen(PORT, () => {
  console.log("==============================================");
  console.log("🎓 CAMPUS PROBLEM INTELLIGENCE SYSTEM");
  console.log("==============================================");
  console.log("URL: http://localhost:" + PORT);
  console.log("Database: campus.db");
  console.log("Student Demo: student / student123");
  console.log("Department Demo: it / admin123");
  console.log("==============================================");
});
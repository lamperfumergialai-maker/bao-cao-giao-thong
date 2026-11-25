const express = require("express");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const archiver = require("archiver");
const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const REPORTS_FILE = path.join(DATA_DIR, "reports.json");
const MAX_FILE_BYTES = 20 * 1024 * 1024;
const MAX_BACKUP_BYTES = 100 * 1024 * 1024;

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error("Thiếu ADMIN_PASSWORD hoặc mật khẩu dưới 12 ký tự.");
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Thiếu SESSION_SECRET hoặc khóa bí mật dưới 32 ký tự.");
  process.exit(1);
}

fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(REPORTS_FILE)) fs.writeFileSync(REPORTS_FILE, "[]", "utf8");

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://unpkg.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      imgSrc: ["'self'", "data:", "https://*.tile.openstreetmap.org"],
      connectSrc: ["'self'"],
      mediaSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginResourcePolicy: { policy: "same-site" }
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, message: "Bạn đã thử đăng nhập quá nhiều lần. Vui lòng thử lại sau 15 phút." }
});
const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, message: "Bạn đã gửi quá nhiều phản ánh. Vui lòng thử lại sau." }
});

const allowedMime = new Set(["image/jpeg", "image/png", "image/webp", "image/gif", "video/mp4", "video/webm", "video/quicktime"]);
const allowedExt = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif", ".mp4", ".webm", ".mov"]);

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    if (allowedMime.has(file.mimetype) && allowedExt.has(ext)) return cb(null, true);
    cb(new Error("Chỉ chấp nhận ảnh JPG, PNG, WEBP, GIF hoặc video MP4, WEBM, MOV."));
  }
});
const backupUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_BACKUP_BYTES, files: 1 }
});

function readReports() {
  try {
    const parsed = JSON.parse(fs.readFileSync(REPORTS_FILE, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    throw new Error("Không đọc được dữ liệu reports.json. Hãy phục hồi từ bản sao lưu.");
  }
}
let writeQueue = Promise.resolve();
function saveReports(reports) {
  const task = writeQueue.then(async () => {
    const temp = `${REPORTS_FILE}.${crypto.randomUUID()}.tmp`;
    await fs.promises.writeFile(temp, JSON.stringify(reports, null, 2), "utf8");
    await fs.promises.rename(temp, REPORTS_FILE);
  });
  writeQueue = task.catch(() => {});
  return task;
}
function cleanText(value, max = 2000) {
  return String(value || "").trim().slice(0, max);
}
function validPhone(value) {
  return /^[0-9+\s().-]{8,20}$/.test(String(value || "").trim());
}
function makeId() {
  const d = new Date();
  const stamp = d.toISOString().replace(/[-:TZ.]/g, "").slice(0, 14);
  return `GT-${stamp}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}
function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function setAdminCookie(res) {
  const expires = Date.now() + 8 * 60 * 60 * 1000;
  const payload = String(expires);
  const token = `${payload}.${sign(payload)}`;
  res.cookie("gt_admin", token, {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 8 * 60 * 60 * 1000,
    path: "/"
  });
}
function requireAdmin(req, res, next) {
  const token = req.cookies?.gt_admin;
  if (!token) return res.status(401).json({ success: false, message: "Vui lòng đăng nhập quản trị." });
  const [expires, signature] = token.split(".");
  if (!expires || !signature || Number(expires) < Date.now() || !safeEqual(sign(expires), signature)) {
    res.clearCookie("gt_admin", { path: "/" });
    return res.status(401).json({ success: false, message: "Phiên đăng nhập đã hết hạn." });
  }
  next();
}
// Cookie parser nhỏ, không cần thêm thư viện.
app.use((req, _res, next) => {
  req.cookies = {};
  (req.headers.cookie || "").split(";").forEach(part => {
    const i = part.indexOf("=");
    if (i > 0) req.cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  next();
});

app.get("/api/health", (_req, res) => res.json({ success: true, service: "traffic-reporting" }));

app.post("/api/report", reportLimiter, (req, res, next) => {
  upload.single("media")(req, res, async err => {
    if (err) return next(err);
    try {
      const fullName = cleanText(req.body.fullName, 120);
      const phone = cleanText(req.body.phone, 30);
      const location = cleanText(req.body.location, 500);
      const description = cleanText(req.body.description, 3000);
      const latitude = req.body.latitude === "" || req.body.latitude == null ? null : Number(req.body.latitude);
      const longitude = req.body.longitude === "" || req.body.longitude == null ? null : Number(req.body.longitude);
      if (!fullName || !validPhone(phone) || !location || !description || !req.file) {
        if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
        return res.status(400).json({ success: false, message: "Vui lòng nhập đủ thông tin, số điện thoại hợp lệ và tệp minh chứng." });
      }
      if ((latitude !== null && (!Number.isFinite(latitude) || Math.abs(latitude) > 90)) ||
          (longitude !== null && (!Number.isFinite(longitude) || Math.abs(longitude) > 180))) {
        await fs.promises.unlink(req.file.path).catch(() => {});
        return res.status(400).json({ success: false, message: "Tọa độ GPS không hợp lệ." });
      }
      const reports = readReports();
      const report = {
        id: makeId(),
        fullName, phone, location, description,
        latitude, longitude,
        fileName: req.file.filename,
        originalFileName: cleanText(req.file.originalname, 180),
        mimeType: req.file.mimetype,
        fileSize: req.file.size,
        category: "Chưa phân loại",
        status: "Mới tiếp nhận",
        processingNote: "",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
      reports.push(report);
      await saveReports(reports);
      res.status(201).json({ success: true, message: "Đã tiếp nhận phản ánh thành công!", reportId: report.id });
    } catch (error) {
      if (req.file) await fs.promises.unlink(req.file.path).catch(() => {});
      next(error);
    }
  });
});

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const password = String(req.body.password || "");
  if (!safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ success: false, message: "Mật khẩu quản trị không đúng." });
  }
  setAdminCookie(res);
  res.json({ success: true, message: "Đăng nhập thành công." });
});
app.post("/api/admin/logout", (_req, res) => {
  res.clearCookie("gt_admin", { path: "/" });
  res.json({ success: true });
});
app.get("/api/admin/me", requireAdmin, (_req, res) => res.json({ success: true }));

app.get("/api/admin/reports", requireAdmin, (req, res, next) => {
  try {
    const reports = readReports().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const q = cleanText(req.query.q, 200).toLocaleLowerCase("vi");
    const category = cleanText(req.query.category, 100);
    const status = cleanText(req.query.status, 100);
    const from = req.query.from ? new Date(req.query.from) : null;
    const to = req.query.to ? new Date(`${req.query.to}T23:59:59.999`) : null;
    const filtered = reports.filter(r => {
      const haystack = [r.id, r.fullName, r.phone, r.location, r.description].join(" ").toLocaleLowerCase("vi");
      const date = new Date(r.createdAt);
      return (!q || haystack.includes(q)) &&
        (!category || r.category === category) &&
        (!status || r.status === status) &&
        (!from || date >= from) && (!to || date <= to);
    });
    res.json({ success: true, reports: filtered });
  } catch (e) { next(e); }
});

app.patch("/api/admin/reports/:id", requireAdmin, async (req, res, next) => {
  try {
    const categories = ["Chưa phân loại", "Ổ gà / mặt đường", "Biển báo giao thông", "Đèn tín hiệu", "Ùn tắc giao thông", "Tai nạn / sự cố", "Lấn chiếm lòng lề đường", "Hạ tầng giao thông", "Khác"];
    const statuses = ["Mới tiếp nhận", "Đã phân công", "Đang xử lý", "Đã xử lý", "Không thuộc thẩm quyền"];
    const reports = readReports();
    const index = reports.findIndex(r => r.id === req.params.id);
    if (index < 0) return res.status(404).json({ success: false, message: "Không tìm thấy phản ánh." });
    const category = cleanText(req.body.category, 100);
    const status = cleanText(req.body.status, 100);
    const processingNote = cleanText(req.body.processingNote, 3000);
    if (!categories.includes(category) || !statuses.includes(status)) {
      return res.status(400).json({ success: false, message: "Loại phản ánh hoặc trạng thái không hợp lệ." });
    }
    reports[index] = { ...reports[index], category, status, processingNote, updatedAt: new Date().toISOString() };
    await saveReports(reports);
    res.json({ success: true, report: reports[index] });
  } catch (e) { next(e); }
});

app.get("/api/admin/media/:filename", requireAdmin, (req, res) => {
  const filename = path.basename(req.params.filename);
  if (filename !== req.params.filename) return res.sendStatus(400);
  const fullPath = path.join(UPLOAD_DIR, filename);
  if (!fs.existsSync(fullPath)) return res.sendStatus(404);
  res.setHeader("Cache-Control", "private, no-store");
  res.sendFile(fullPath);
});

app.get("/api/admin/backup", requireAdmin, (_req, res, next) => {
  try {
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="sao_luu_phan_anh_${new Date().toISOString().slice(0,10)}.zip"`);
    const archive = archiver("zip", { zlib: { level: 6 } });
    archive.on("error", next);
    archive.pipe(res);
    archive.file(REPORTS_FILE, { name: "data/reports.json" });
    archive.directory(UPLOAD_DIR, "uploads");
    archive.finalize();
  } catch (e) { next(e); }
});

app.post("/api/admin/restore", requireAdmin, (req, res, next) => {
  backupUpload.single("backup")(req, res, async err => {
    if (err) return next(err);
    try {
      if (!req.file) return res.status(400).json({ success: false, message: "Chưa chọn tệp sao lưu." });
      const zip = new AdmZip(req.file.buffer);
      const entries = zip.getEntries();
      const reportEntry = entries.find(e => e.entryName === "data/reports.json");
      if (!reportEntry) return res.status(400).json({ success: false, message: "Tệp sao lưu không có data/reports.json." });
      const restored = JSON.parse(reportEntry.getData().toString("utf8"));
      if (!Array.isArray(restored)) return res.status(400).json({ success: false, message: "Dữ liệu sao lưu không hợp lệ." });
      for (const entry of entries) {
        if (entry.isDirectory) continue;
        const name = entry.entryName.replace(/\\/g, "/");
        if (name.startsWith("/") || name.split("/").includes("..")) {
          return res.status(400).json({ success: false, message: "Tệp sao lưu chứa đường dẫn không an toàn." });
        }
        if (name.startsWith("uploads/")) {
          const filename = path.basename(name);
          if (filename !== name.slice("uploads/".length)) continue;
          await fs.promises.writeFile(path.join(UPLOAD_DIR, filename), entry.getData());
        }
      }
      await saveReports(restored);
      res.json({ success: true, message: `Đã phục hồi ${restored.length} phản ánh. Tệp minh chứng có trong bản sao lưu đã được khôi phục.` });
    } catch (e) {
      res.status(400).json({ success: false, message: "Không thể phục hồi. Tệp ZIP hoặc dữ liệu không hợp lệ." });
    }
  });
});

// Chỉ công khai hai trang giao diện, tuyệt đối không public thư mục gốc/data/uploads.
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));

app.use((err, _req, res, _next) => {
  console.error(err.message);
  if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ success: false, message: "Tệp vượt quá giới hạn 20MB." });
  }
  res.status(500).json({ success: false, message: err.message || "Lỗi máy chủ." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Hệ thống đang chạy tại cổng ${PORT}`);
});

import express   from "express";
import cors      from "cors";
import { createClient } from "@supabase/supabase-js";
import bcrypt    from "bcryptjs";
import jwt       from "jsonwebtoken";
import multer    from "multer";
import rateLimit from "express-rate-limit";

const app        = express();
const PORT       = process.env.PORT || 10000;
const JWT_EXPIRY = "7d";

app.set("trust proxy", 1);

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 3 * 1024 * 1024 },
});

// ── Middlewares ─────────────────────────────────────────────
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","OPTIONS"] }));
app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 60_000, max: 200 }));

// ── Auth middleware ─────────────────────────────────────────
function requireAuth(req, res, next) {
  try {
    const header = req.headers["authorization"];
    if (!header?.startsWith("Bearer "))
      return res.status(401).json({ success: false, error: "No autorizado." });

    const token   = header.split(" ")[1];
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.auth      = payload;
    next();
  } catch (e) {
    if (e.name === "TokenExpiredError")
      return res.status(401).json({ success: false, error: "Sesión expirada." });
    res.status(401).json({ success: false, error: "Token inválido." });
  }
}

// ── Helpers de validación para tamaños y sabores ────────────
function normalizarTamanos(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((t) => ({
      nombre: String(t?.nombre || "").trim(),
      precio: Number(t?.precio),
    }))
    .filter((t) => t.nombre && !isNaN(t.precio) && t.precio >= 0);
}

function normalizarSabores(input) {
  if (!Array.isArray(input)) return [];
  return input
    .map((s) => String(s || "").trim())
    .filter(Boolean);
}

// ── Rutas base ──────────────────────────────────────────────
app.get("/",       (_, res) => res.json({ status: "online" }));
app.get("/health", (_, res) => res.json({ status: "ok" }));

// ── POST /auth/login ────────────────────────────────────────
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: "Faltan email y contraseña." });

    const { data: user, error } = await supabase
      .from("admin_users")
      .select("id, email, password")
      .eq("email", email.trim().toLowerCase())
      .maybeSingle();

    if (error) throw error;
    if (!user)
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const ok = await bcrypt.compare(String(password), String(user.password));
    if (!ok)
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({ success: true, token, email: user.email });
  } catch (e) {
    console.error("Error login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── GET /auth/me ────────────────────────────────────────────
app.get("/auth/me", requireAuth, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("admin_users")
      .select("id, email")
      .eq("id", req.auth.userId)
      .maybeSingle();

    if (error) throw error;
    if (!user)
      return res.status(401).json({ success: false, error: "Usuario no encontrado." });

    res.json({ success: true, email: user.email });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── POST /productos/upload-imagen ───────────────────────────
app.post("/productos/upload-imagen", requireAuth, upload.single("imagen"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ success: false, error: "No se recibió imagen." });

    const ext      = req.file.mimetype === "image/png"  ? "png"
                   : req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const fileName = `yoe/${Date.now()}.${ext}`;

    const { error } = await supabase.storage
      .from("productos")
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });

    if (error) throw error;

    const { data } = supabase.storage.from("productos").getPublicUrl(fileName);
    res.json({ success: true, imagen_url: data.publicUrl });  // ← clave: imagen_url
  } catch (e) {
    console.error("Error upload:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── GET /productos (admin — todos) ──────────────────────────
app.get("/productos", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("productos")
      .select("*")
      .order("orden",      { ascending: true })
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json(data || []);   // ← devuelve array directo, como espera el panel
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── GET /catalogo (público — solo activos) ──────────────────
app.get("/catalogo", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("productos")
      .select("id, nombre, descripcion, precio, imagen_url, categoria, unidad_venta, tamanos, sabores")
      .eq("activo", true)
      .order("orden",      { ascending: true })
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, productos: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── POST /productos ─────────────────────────────────────────
app.post("/productos", requireAuth, async (req, res) => {
  try {
    const { nombre, precio, categoria, descripcion, imagen_url, activo, orden, unidad_venta, tamanos, sabores } = req.body;

    if (!nombre || precio === undefined)
      return res.status(400).json({ success: false, error: "Faltan nombre y precio." });

    const { data, error } = await supabase
      .from("productos")
      .insert([{
        nombre:        nombre.trim(),
        precio:        Number(precio),
        categoria:     categoria?.trim()   || null,
        descripcion:   descripcion?.trim() || null,
        imagen_url:    imagen_url          || null,
        activo:        activo !== undefined ? Boolean(activo) : true,
        orden:         parseInt(orden)     || 0,
        unidad_venta:  unidad_venta?.trim() || null,
        tamanos:       normalizarTamanos(tamanos),
        sabores:       normalizarSabores(sabores),
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);   // ← devuelve objeto directo
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── PUT /productos/:id ──────────────────────────────────────
app.put("/productos/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { nombre, precio, categoria, descripcion, imagen_url, activo, orden, unidad_venta, tamanos, sabores } = req.body;

    const u = {};
    if (nombre       !== undefined) u.nombre       = nombre.trim();
    if (precio       !== undefined) u.precio       = Number(precio);
    if (categoria    !== undefined) u.categoria    = categoria?.trim() || null;
    if (descripcion  !== undefined) u.descripcion  = descripcion?.trim() || null;
    if (imagen_url   !== undefined) u.imagen_url   = imagen_url || null;
    if (activo       !== undefined) u.activo       = Boolean(activo);
    if (orden        !== undefined) u.orden        = parseInt(orden);
    if (unidad_venta !== undefined) u.unidad_venta = unidad_venta?.trim() || null;
    if (tamanos      !== undefined) u.tamanos      = normalizarTamanos(tamanos);
    if (sabores       !== undefined) u.sabores     = normalizarSabores(sabores);

    const { data, error } = await supabase
      .from("productos")
      .update(u)
      .eq("id", id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);   // ← devuelve objeto directo
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── DELETE /productos/:id ───────────────────────────────────
app.delete("/productos/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabase
      .from("productos")
      .delete()
      .eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`Panel Productos API — puerto ${PORT}`);
});

export default app;

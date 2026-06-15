import express   from "express";
import cors      from "cors";
import { createClient } from "@supabase/supabase-js";
import bcrypt    from "bcryptjs";
import jwt       from "jsonwebtoken";
import multer    from "multer";
import rateLimit from "express-rate-limit";

// ══════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════
// MIDDLEWARES
// ══════════════════════════════════════════════════════════════
app.use(cors({ origin: "*", methods: ["GET","POST","PUT","DELETE","OPTIONS"] }));
app.use(express.json({ limit: "10mb" }));
app.use(rateLimit({ windowMs: 60_000, max: 200 }));

// ══════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════
const cleanSlug = (raw = "") =>
  raw.toLowerCase().trim()
    .normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");

// ══════════════════════════════════════════════════════════════
// MIDDLEWARE AUTH
// ══════════════════════════════════════════════════════════════
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

// ══════════════════════════════════════════════════════════════
// RUTAS BASE
// ══════════════════════════════════════════════════════════════
app.get("/",       (_, res) => res.json({ status: "online", service: "panel-productos" }));
app.get("/health", (_, res) => res.json({ status: "ok" }));

// ══════════════════════════════════════════════════════════════
// LOGIN — usa la misma tabla usuarios de Associe
// POST /login
// ══════════════════════════════════════════════════════════════
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, error: "Faltan email y contraseña." });

    const { data: user, error } = await supabase
      .from("usuarios")
      .select("id, slug, password, business_name, nombre_persona, activo")
      .eq("email", email.trim().toLowerCase())
      .maybeSingle();

    if (error) throw error;
    if (!user)
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    const ok = await bcrypt.compare(String(password), String(user.password));
    if (!ok)
      return res.status(401).json({ success: false, error: "Credenciales incorrectas." });

    if (user.activo !== "true" && user.activo !== true)
      return res.status(403).json({ success: false, error: "Cuenta desactivada." });

    const token = jwt.sign(
      { slug: user.slug, negocioId: user.id, rol: "owner" },
      process.env.JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({
      success:       true,
      token,
      slug:          user.slug,
      business_name: user.business_name,
      nombre:        user.nombre_persona,
    });
  } catch (e) {
    console.error("Error login:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// VERIFY SESSION
// GET /verify-session
// ══════════════════════════════════════════════════════════════
app.get("/verify-session", async (req, res) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) return res.json({ active: false });

    const payload    = jwt.verify(token, process.env.JWT_SECRET);
    const { data: user } = await supabase
      .from("usuarios")
      .select("slug, business_name, activo")
      .eq("slug", payload.slug)
      .maybeSingle();

    if (!user || (user.activo !== "true" && user.activo !== true))
      return res.json({ active: false });

    res.json({ active: true, slug: user.slug, business_name: user.business_name });
  } catch {
    res.json({ active: false });
  }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTOS — UPLOAD IMAGEN
// POST /admin/productos/upload-imagen
// ══════════════════════════════════════════════════════════════
app.post("/admin/productos/upload-imagen", requireAuth, upload.single("imagen"), async (req, res) => {
  try {
    const slug = cleanSlug(req.body.slug || req.auth.slug);
    if (!req.file)
      return res.status(400).json({ success: false, error: "No se recibió imagen." });

    const ext      = req.file.mimetype === "image/png" ? "png"
                   : req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const fileName = `${slug}/${Date.now()}.${ext}`;

    const { error } = await supabase.storage
      .from("productos")
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });

    if (error) throw error;

    const { data } = supabase.storage.from("productos").getPublicUrl(fileName);
    res.json({ success: true, url: data.publicUrl });
  } catch (e) {
    console.error("Error upload imagen:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTOS — GET admin
// GET /admin/productos/:slug
// ══════════════════════════════════════════════════════════════
app.get("/admin/productos/:slug", requireAuth, async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase
      .from("productos")
      .select("*")
      .eq("slug", slug)
      .order("orden",      { ascending: true })
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, productos: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTOS — GET público (para clientes)
// GET /productos/:slug
// ══════════════════════════════════════════════════════════════
app.get("/productos/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    const { data, error } = await supabase
      .from("productos")
      .select("id, nombre, descripcion, precio, imagen_url, categoria")
      .eq("slug", slug)
      .eq("activo", true)
      .order("orden",      { ascending: true })
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, productos: data || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


app.post("/admin/productos", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, precio, categoria, descripcion, imagen_url, activo, orden } = req.body;
    const slugClean = cleanSlug(slug || req.auth.slug);

    if (!slugClean || !nombre || precio === undefined)
      return res.status(400).json({ success: false, error: "Faltan campos: nombre y precio." });

    const { data, error } = await supabase
      .from("productos")
      .insert([{
        slug:        slugClean,
        nombre:      nombre.trim(),
        precio:      Number(precio),
        categoria:   categoria?.trim()   || null,
        descripcion: descripcion?.trim() || null,
        imagen_url:  imagen_url          || null,
        activo:      activo !== undefined ? Boolean(activo) : true,
        orden:       parseInt(orden)     || 0,
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json({ success: true, producto: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTOS — PUT editar
// PUT /admin/productos/:id
// ══════════════════════════════════════════════════════════════
app.put("/admin/productos/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const slugClean = cleanSlug(req.body.slug || req.auth.slug);
    const { nombre, precio, categoria, descripcion, imagen_url, activo, orden } = req.body;

    const u = {};
    if (nombre      !== undefined) u.nombre      = nombre.trim();
    if (precio      !== undefined) u.precio      = Number(precio);
    if (categoria   !== undefined) u.categoria   = categoria?.trim() || null;
    if (descripcion !== undefined) u.descripcion = descripcion?.trim() || null;
    if (imagen_url  !== undefined) u.imagen_url  = imagen_url || null;
    if (activo      !== undefined) u.activo      = Boolean(activo);
    if (orden       !== undefined) u.orden       = parseInt(orden);

    const { data, error } = await supabase
      .from("productos")
      .update(u)
      .eq("id", id)
      .eq("slug", slugClean)
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, producto: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// PRODUCTOS — DELETE
// DELETE /admin/productos/:id
// ══════════════════════════════════════════════════════════════
app.delete("/admin/productos/:id", requireAuth, async (req, res) => {
  try {
    const { id }    = req.params;
    const slugClean = cleanSlug(req.body?.slug || req.query?.slug || req.auth.slug);
    const { error } = await supabase
      .from("productos")
      .delete()
      .eq("id", id)
      .eq("slug", slugClean);
    if (error) throw error;
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
// ARRANQUE
// ══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`Panel Productos API — puerto ${PORT}`);
});

export default app;

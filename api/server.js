// ══════════════════════════════════════════════════════════════
// PRODUCTOS — Pegá estas rutas en tu server.js (index.js)
// Van después de las rutas de servicios, mismo patrón exacto
// ══════════════════════════════════════════════════════════════

// ── UPLOAD IMAGEN (antes que /:id para que no colisione) ──────
app.post("/admin/productos/upload-imagen", requireAuth, upload.single("imagen"), async (req, res) => {
  try {
    const slug = cleanSlug(req.body.slug || req.auth.slug);
    if (!req.file) return res.status(400).json({ success: false, error: "No se recibió imagen." });

    const ext      = req.file.mimetype === "image/png" ? "png" : req.file.mimetype === "image/webp" ? "webp" : "jpg";
    const fileName = `${slug}/${Date.now()}.${ext}`;

    const { error } = await supabase.storage
      .from("productos")
      .upload(fileName, req.file.buffer, { contentType: req.file.mimetype, upsert: true });

    if (error) throw error;

    const { data } = supabase.storage.from("productos").getPublicUrl(fileName);
    res.json({ success: true, url: data.publicUrl });
  } catch (e) {
    console.error("Error upload imagen producto:", e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── GET todos los productos del negocio (admin) ───────────────
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

// ── GET productos públicos (para el megacomponente de clientes) ─
app.get("/productos/:slug", async (req, res) => {
  try {
    const slug = cleanSlug(req.params.slug);
    if (!slug) return res.status(400).json({ success: false, error: "Slug inválido." });
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

// ── POST crear producto ───────────────────────────────────────
app.post("/admin/productos", requireAuth, async (req, res) => {
  try {
    const { slug, nombre, precio, categoria, descripcion, imagen_url, activo, orden } = req.body;
    const slugClean = cleanSlug(slug || req.auth.slug);

    if (!slugClean || !nombre || precio === undefined) {
      return res.status(400).json({ success: false, error: "Faltan campos: nombre y precio." });
    }

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
    invalidateCache(slugClean);
    res.status(201).json({ success: true, producto: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── PUT editar producto ───────────────────────────────────────
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
    invalidateCache(slugClean);
    res.json({ success: true, producto: data });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── DELETE producto ───────────────────────────────────────────
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
    invalidateCache(slugClean);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

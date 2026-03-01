require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();
const app = express();

const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5500";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

// Recomendado: ".limine.io" (con punto) para compartir cookie entre subdominios
const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN || undefined;

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: CORS_ORIGIN.split(",").map((s) => s.trim()),
    credentials: true,
  })
);

// ---------- helpers ----------
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) return res.status(401).json({ error: "No autenticado" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user?.role) return res.status(401).json({ error: "No autenticado" });
    if (req.user.role !== role) return res.status(403).json({ error: "Sin permisos" });
    next();
  };
}

function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
    domain: COOKIE_DOMAIN,
  });
}

// ---------- health ----------
app.get("/health", (req, res) => res.json({ ok: true }));

// ---------- public catalog ----------
app.get(
  "/products",
  asyncHandler(async (req, res) => {
    const products = await prisma.product.findMany({
      where: { isActive: true },
      orderBy: { createdAt: "desc" },
    });
    res.json(products);
  })
);

app.get(
  "/courses",
  asyncHandler(async (req, res) => {
    const courses = await prisma.course.findMany({
      where: { isActive: true },
      orderBy: { createdAt: "desc" },
    });
    res.json(courses);
  })
);

// ---------- auth ----------
app.post(
  "/auth/register",
  asyncHandler(async (req, res) => {
    const { email, password, name } = req.body ?? {};

    if (!email || !password) {
      return res.status(400).json({ error: "Falta email o password" });
    }
    if (typeof password !== "string" || password.length < 8) {
      return res.status(400).json({ error: "Password mínimo 8 caracteres" });
    }

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "Ese correo ya existe" });

    const passHash = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: { email, name: name || null, passHash },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });

    const token = signToken(user);
    setAuthCookie(res, token);

    res.json(user);
  })
);

app.post(
  "/auth/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body ?? {};
    if (!email || !password) {
      return res.status(400).json({ error: "Falta email o password" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

    const ok = await bcrypt.compare(password, user.passHash);
    if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = signToken(user);
    setAuthCookie(res, token);

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
    });
  })
);

app.post("/auth/logout", (req, res) => {
  // Debe coincidir con cómo se creó la cookie
  res.clearCookie("token", {
    domain: COOKIE_DOMAIN,
    secure: COOKIE_SECURE,
    sameSite: "lax",
  });
  res.json({ ok: true });
});

app.get(
  "/me",
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = await prisma.user.findUnique({
      where: { id: req.user.sub },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(me);
  })
);

// ---------- orders (customer) ----------
app.post(
  "/orders",
  requireAuth,
  asyncHandler(async (req, res) => {
    const { items } = req.body ?? {};

    if (!Array.isArray(items) || items.length < 1) {
      return res.status(400).json({ error: "Items inválidos" });
    }

    let totalCents = 0;
    const normalizedItems = [];

    for (const it of items) {
      const qty = Number(it.qty ?? 1);
      const productId = it.productId ?? null;
      const courseId = it.courseId ?? null;
      const variant = it.variant ?? null;

      if (!Number.isInteger(qty) || qty < 1) {
        return res.status(400).json({ error: "qty inválido" });
      }

      if ((!!productId && !!courseId) || (!productId && !courseId)) {
        return res
          .status(400)
          .json({ error: "Cada item debe tener productId o courseId (solo uno)" });
      }

      if (productId) {
        const p = await prisma.product.findUnique({ where: { id: productId } });
        if (!p || !p.isActive) return res.status(400).json({ error: "Producto inválido" });

        totalCents += p.priceCents * qty;
        normalizedItems.push({ productId: p.id, qty, unitCents: p.priceCents, variant });
      }

      if (courseId) {
        const c = await prisma.course.findUnique({ where: { id: courseId } });
        if (!c || !c.isActive) return res.status(400).json({ error: "Curso inválido" });

        totalCents += c.priceCents * qty;
        normalizedItems.push({ courseId: c.id, qty, unitCents: c.priceCents });
      }
    }

    const order = await prisma.order.create({
      data: {
        userId: req.user.sub,
        totalCents,
        items: { create: normalizedItems },
      },
      include: { items: { include: { product: true, course: true } } },
    });

    res.json(order);
  })
);

app.get(
  "/orders",
  requireAuth,
  asyncHandler(async (req, res) => {
    const orders = await prisma.order.findMany({
      where: { userId: req.user.sub },
      orderBy: { createdAt: "desc" },
      include: { items: { include: { product: true, course: true } } },
    });

    res.json(orders);
  })
);

app.get(
  "/orders/current",
  requireAuth,
  asyncHandler(async (req, res) => {
    const order = await prisma.order.findFirst({
      where: {
        userId: req.user.sub,
        status: { in: ["PENDING_PAYMENT", "PAID", "REVIEW", "IN_PRODUCTION", "SHIPPED"] },
      },
      orderBy: { createdAt: "desc" },
      include: { items: { include: { product: true, course: true } } },
    });

    res.json(order ?? null);
  })
);

// =====================================================
// ===================== ADMIN CRUD =====================
// =====================================================

// ---- schemas ----
const ProductCreateSchema = z.object({
  name: z.string().min(2),
  description: z.string().optional().nullable(),
  priceCents: z.number().int().nonnegative(),
  category: z.string().optional().nullable(),
  isActive: z.boolean().optional(),
});
const ProductUpdateSchema = ProductCreateSchema.partial();

const CourseCreateSchema = z.object({
  title: z.string().min(2),
  description: z.string().optional().nullable(),
  priceCents: z.number().int().nonnegative(),
  isActive: z.boolean().optional(),
});
const CourseUpdateSchema = CourseCreateSchema.partial();

const OrderStatusSchema = z.enum([
  "PENDING_PAYMENT",
  "PAID",
  "REVIEW",
  "IN_PRODUCTION",
  "SHIPPED",
  "DELIVERED",
  "CANCELLED",
]);

// ---- admin: products ----
app.get(
  "/admin/products",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const products = await prisma.product.findMany({ orderBy: { createdAt: "desc" } });
    res.json(products);
  })
);

app.post(
  "/admin/products",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const data = ProductCreateSchema.parse(req.body);
    const created = await prisma.product.create({
      data: {
        name: data.name,
        description: data.description ?? null,
        priceCents: data.priceCents,
        category: data.category ?? null,
        isActive: data.isActive ?? true,
      },
    });
    res.status(201).json(created);
  })
);

app.patch(
  "/admin/products/:id",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const data = ProductUpdateSchema.parse(req.body);
    const updated = await prisma.product.update({
      where: { id: req.params.id },
      data: {
        ...(data.name !== undefined ? { name: data.name } : {}),
        ...(data.description !== undefined ? { description: data.description } : {}),
        ...(data.priceCents !== undefined ? { priceCents: data.priceCents } : {}),
        ...(data.category !== undefined ? { category: data.category } : {}),
        ...(data.isActive !== undefined ? { isActive: data.isActive } : {}),
      },
    });
    res.json(updated);
  })
);

app.delete(
  "/admin/products/:id",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const updated = await prisma.product.update({
      where: { id: req.params.id },
      data: { isActive: false },
    });
    res.json({ ok: true, product: updated });
  })
);

// ---- admin: courses ----
app.get(
  "/admin/courses",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const courses = await prisma.course.findMany({ orderBy: { createdAt: "desc" } });
    res.json(courses);
  })
);

app.post(
  "/admin/courses",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const data = CourseCreateSchema.parse(req.body);
    const created = await prisma.course.create({
      data: {
        title: data.title,
        description: data.description ?? null,
        priceCents: data.priceCents,
        isActive: data.isActive ?? true,
      },
    });
    res.status(201).json(created);
  })
);

app.patch(
  "/admin/courses/:id",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const data = CourseUpdateSchema.parse(req.body);
    const updated = await prisma.course.update({
      where: { id: req.params.id },
      data: {
        ...(data.title !== undefined ? { title: data.title } : {}),
        ...(data.description !== undefined ? { description: data.description } : {}),
        ...(data.priceCents !== undefined ? { priceCents: data.priceCents } : {}),
        ...(data.isActive !== undefined ? { isActive: data.isActive } : {}),
      },
    });
    res.json(updated);
  })
);

app.delete(
  "/admin/courses/:id",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const updated = await prisma.course.update({
      where: { id: req.params.id },
      data: { isActive: false },
    });
    res.json({ ok: true, course: updated });
  })
);

// ---- admin: orders ----
app.get(
  "/admin/orders",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const orders = await prisma.order.findMany({
      orderBy: { createdAt: "desc" },
      include: { items: { include: { product: true, course: true } }, user: true },
    });
    res.json(orders);
  })
);

app.patch(
  "/admin/orders/:id/status",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const { status } = z.object({ status: OrderStatusSchema }).parse(req.body);
    const updated = await prisma.order.update({
      where: { id: req.params.id },
      data: { status },
    });
    res.json(updated);
  })
);

// ---- admin: users ----
app.get(
  "/admin/users",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const users = await prisma.user.findMany({
      orderBy: { createdAt: "desc" },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(users);
  })
);

app.patch(
  "/admin/users/:id/role",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const { role } = z.object({ role: z.string().min(3) }).parse(req.body);
    const updated = await prisma.user.update({
      where: { id: req.params.id },
      data: { role },
      select: { id: true, email: true, name: true, role: true, createdAt: true },
    });
    res.json(updated);
  })
);

// ---------- error handler ----------
app.use((err, req, res, next) => {
  if (err?.name === "ZodError") {
    return res.status(400).json({ error: "Datos inválidos", details: err.errors });
  }
  console.error(err);
  res.status(500).json({ error: "Error interno" });
});

// ---------- start ----------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("API lista en puerto", port));

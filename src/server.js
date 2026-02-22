require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();
const app = express();

const CORS_ORIGIN = process.env.CORS_ORIGIN || "http://localhost:5500";
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(
  cors({
    origin: CORS_ORIGIN.split(",").map((s) => s.trim()),
    credentials: true,
  })
);

// -------- helpers auth --------
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

// -------- health --------
app.get("/health", (req, res) => res.json({ ok: true }));

// -------- catalog --------
app.get("/products", async (req, res) => {
  const products = await prisma.product.findMany({ where: { isActive: true } });
  res.json(products);
});

app.get("/courses", async (req, res) => {
  const courses = await prisma.course.findMany({ where: { isActive: true } });
  res.json(courses);
});

// -------- auth --------
app.post("/auth/register", async (req, res) => {
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
  res.cookie("token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
  });

  res.json(user);
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (!email || !password) {
    return res.status(400).json({ error: "Falta email o password" });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(401).json({ error: "Credenciales inválidas" });

  const ok = await bcrypt.compare(password, user.passHash);
  if (!ok) return res.status(401).json({ error: "Credenciales inválidas" });

  const token = signToken(user);
  res.cookie("token", token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
  });

  res.json({ id: user.id, email: user.email, name: user.name, role: user.role, createdAt: user.createdAt });
});

app.post("/auth/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/me", requireAuth, async (req, res) => {
  const me = await prisma.user.findUnique({
    where: { id: req.user.sub },
    select: { id: true, email: true, name: true, role: true, createdAt: true },
  });
  res.json(me);
});

// -------- orders --------
app.post("/orders", requireAuth, async (req, res) => {
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

    // exactamente uno: productId o courseId
    if ((!!productId && !!courseId) || (!productId && !courseId)) {
      return res
        .status(400)
        .json({ error: "Cada item debe tener productId o courseId (solo uno)" });
    }

    if (productId) {
      const p = await prisma.product.findUnique({ where: { id: productId } });
      if (!p || !p.isActive) return res.status(400).json({ error: "Producto inválido" });

      totalCents += p.priceCents * qty;
      normalizedItems.push({
        productId: p.id,
        qty,
        unitCents: p.priceCents,
        variant,
      });
    }

    if (courseId) {
      const c = await prisma.course.findUnique({ where: { id: courseId } });
      if (!c || !c.isActive) return res.status(400).json({ error: "Curso inválido" });

      totalCents += c.priceCents * qty;
      normalizedItems.push({
        courseId: c.id,
        qty,
        unitCents: c.priceCents,
      });
    }
  }

  const order = await prisma.order.create({
    data: {
      userId: req.user.sub,
      totalCents,
      items: { create: normalizedItems },
    },
    include: {
      items: { include: { product: true, course: true } },
    },
  });

  res.json(order);
});

app.get("/orders", requireAuth, async (req, res) => {
  const orders = await prisma.order.findMany({
    where: { userId: req.user.sub },
    orderBy: { createdAt: "desc" },
    include: { items: { include: { product: true, course: true } } },
  });

  res.json(orders);
});

app.get("/orders/current", requireAuth, async (req, res) => {
  const order = await prisma.order.findFirst({
    where: {
      userId: req.user.sub,
      status: { in: ["PENDING_PAYMENT", "PAID", "REVIEW", "IN_PRODUCTION", "SHIPPED"] },
    },
    orderBy: { createdAt: "desc" },
    include: { items: { include: { product: true, course: true } } },
  });

  res.json(order ?? null);
});

// -------- start --------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("API lista en puerto", port));
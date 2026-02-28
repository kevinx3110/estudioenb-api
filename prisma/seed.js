const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");
const prisma = new PrismaClient();

async function main() {
  // Productos
  await prisma.product.createMany({
    data: [
      { name: "Playera sublimada", priceCents: 39900, category: "Ropa" },
      { name: "Taza 11oz", priceCents: 21900, category: "Tazas" },
      { name: "Tote bag", priceCents: 29900, category: "Bolsas" },
    ],
    skipDuplicates: true
  });

  // Cursos
  await prisma.course.createMany({
    data: [
      { title: "Sublimación 101", priceCents: 79900 },
      { title: "Diseño para impresión", priceCents: 59900 },
    ],
    skipDuplicates: true
  });

  // Admin (si no existe)
  const adminEmail = "admin@limine.io"; // cámbialo si quieres
  const pass = "CAMBIA-ESTA-CONTRASEÑA"; // y esta también, obvio
  const passHash = await bcrypt.hash(pass, 10);

  await prisma.user.upsert({
    where: { email: adminEmail },
    update: { role: "admin" },
    create: {
      email: adminEmail,
      name: "Admin",
      passHash,
      role: "admin",
    },
  });

  console.log("Seed listo (incluye admin).");
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(async () => { await prisma.$disconnect(); });

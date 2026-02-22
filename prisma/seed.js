const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

async function main() {
  await prisma.product.createMany({
    data: [
      { name: "Playera sublimada", priceCents: 39900, category: "Ropa" },
      { name: "Taza 11oz", priceCents: 21900, category: "Tazas" },
      { name: "Tote bag", priceCents: 29900, category: "Bolsas" },
    ],
    skipDuplicates: true
  });

  await prisma.course.createMany({
    data: [
      { title: "Sublimación 101", priceCents: 79900 },
      { title: "Diseño para impresión", priceCents: 59900 },
    ],
    skipDuplicates: true
  });

  console.log("Seed listo.");
}

main()
  .catch(e => { console.error(e); process.exit(1); })
  .finally(async () => { await prisma.$disconnect(); });
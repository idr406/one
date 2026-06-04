/**
 * scripts/hashear-passwords.js
 * ─────────────────────────────────────────────────────────────────────────────
 * Migración ONE-TIME: hashea con bcrypt todas las contraseñas en texto plano
 * que existan en la tabla `usuarios`.
 *
 * Ejecución (una sola vez, antes de arrancar el servidor con la nueva versión):
 *   node scripts/hashear-passwords.js
 *
 * El script detecta automáticamente si una contraseña YA está hasheada
 * (los hashes bcrypt empiezan con "$2b$" o "$2a$") y las salta sin modificar.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const bcrypt = require('bcryptjs');
const db     = require('../db');

const SALT_ROUNDS = 12;

async function migrar() {
  console.log('\n🔐 Iniciando migración de contraseñas a bcrypt...\n');

  // Obtener todos los usuarios con su contraseña actual
  const [usuarios] = await db.promise().query(
    'SELECT ID_usuario, Nombre, Correo, contraseña_hash FROM usuarios'
  );

  if (usuarios.length === 0) {
    console.log('ℹ️  No hay usuarios en la base de datos. Nada que migrar.');
    process.exit(0);
  }

  let migrados = 0;
  let saltados = 0;

  for (const u of usuarios) {
    const pass = u.contraseña_hash || '';

    // Si ya es un hash bcrypt, no tocar
    if (pass.startsWith('$2b$') || pass.startsWith('$2a$')) {
      console.log(`  ⏭️  [${u.Correo}] — ya tiene hash bcrypt, se omite.`);
      saltados++;
      continue;
    }

    // Hashear la contraseña en texto plano
    const hash = await bcrypt.hash(pass, SALT_ROUNDS);
    await db.promise().query(
      'UPDATE usuarios SET contraseña_hash = ? WHERE ID_usuario = ?',
      [hash, u.ID_usuario]
    );
    console.log(`  ✅  [${u.Correo}] — contraseña hasheada correctamente.`);
    migrados++;
  }

  console.log(`\n✔  Migración completada.`);
  console.log(`   Hasheados: ${migrados} | Omitidos (ya bcrypt): ${saltados}\n`);
  process.exit(0);
}

migrar().catch(err => {
  console.error('\n❌ Error durante la migración:', err.message);
  process.exit(1);
});

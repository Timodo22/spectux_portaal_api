// --- HULPFUNCTIES ---
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// Max logo: 200KB origineel → base64 ≈ 267KB, ruim binnen D1's 1MB rijlimiet
const MAX_LOGO_BYTES = 200 * 1024;

async function hashPassword(password) {
  const msgUint8 = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendEmail(apiKey, to, subject, html) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'Spectux Portaal <noreply@spectux.com>', to: [to], subject, html })
  });
  return res.ok;
}

function getCorsHeaders(request) {
  const allowedOrigins = [
    'http://localhost:8080', 'http://localhost:5173', 'http://localhost:3000',
    'https://spectux.com', 'https://www.spectux.com'
  ];
  const origin = request.headers.get('Origin');
  return {
    "Access-Control-Allow-Origin": allowedOrigins.includes(origin) ? origin : "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status, request) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...getCorsHeaders(request) }
  });
}

const DEMO_BLOCKED = (request) =>
  jsonResponse(
    { error: 'demo_blocked', message: 'Upgrade naar Premium om deze functie te gebruiken.' },
    403, request
  );

// --- MAIN WORKER ---
export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: getCorsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ==========================================
      // 1. PUBLIC AUTH ROUTES
      // ==========================================
      if (path.startsWith('/api/auth/')) {
        if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405, request);

        if (path === '/api/auth/register') {
          const { name, email, password } = await request.json();
          const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
          if (existing) return jsonResponse({ error: 'E-mailadres is al in gebruik' }, 400, request);

          const id = crypto.randomUUID();
          const passwordHash = await hashPassword(password);
          const code = generateCode();
          const expires = new Date(Date.now() + 15 * 60000).toISOString();

          await env.DB.prepare(
            'INSERT INTO users (id, name, email, password_hash, verification_code, verification_expires, plan_factuur, plan_planner) VALUES (?, ?, ?, ?, ?, ?, 0, 0)'
          ).bind(id, name, email, passwordHash, code, expires).run();

          await sendEmail(env.RESEND_API_KEY, email, 'Verifieer je Spectux account',
            `<div style="font-family:sans-serif;max-width:480px;margin:auto">
              <h2>Welkom bij Spectux, ${name}!</h2>
              <p>Gebruik de onderstaande code om je account te verifiëren:</p>
              <div style="background:#f4f4f5;border-radius:8px;padding:24px;text-align:center;font-size:36px;font-weight:bold;letter-spacing:8px">${code}</div>
              <p style="color:#71717a;font-size:14px">Deze code verloopt over 15 minuten.</p>
            </div>`
          );
          return jsonResponse({ message: 'Code verstuurd' }, 200, request);
        }

        if (path === '/api/auth/verify') {
          const { email, code } = await request.json();
          const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(email, code).first();
          if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
          if (new Date(user.verification_expires) < new Date()) return jsonResponse({ error: 'Code is verlopen' }, 400, request);
          await env.DB.prepare('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(email).run();
          return jsonResponse({ message: 'Account geverifieerd' }, 200, request);
        }

        if (path === '/api/auth/login') {
          const { email, password } = await request.json();
          const passwordHash = await hashPassword(password);
          const user = await env.DB.prepare(
            'SELECT id, name, is_verified, plan_factuur, plan_planner FROM users WHERE email = ? AND password_hash = ?'
          ).bind(email, passwordHash).first();
          if (!user) return jsonResponse({ error: 'Ongeldige inloggegevens' }, 401, request);
          if (user.is_verified === 0) return jsonResponse({ error: 'Account is niet geverifieerd' }, 403, request);

          return jsonResponse({
            message: 'Succesvol ingelogd',
            token: user.id,
            user: {
              id: user.id,
              name: user.name,
              plans: { factuur: Boolean(user.plan_factuur), planner: Boolean(user.plan_planner) }
            }
          }, 200, request);
        }
      }

      // ==========================================
      // 2. PROTECTED ROUTES
      // ==========================================
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);
      }
      const userId = authHeader.split(" ")[1];

      const userRecord = await env.DB.prepare(
        'SELECT id, plan_factuur, plan_planner FROM users WHERE id = ?'
      ).bind(userId).first();
      if (!userRecord) return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);

      const hasFactuurPlan = Boolean(userRecord.plan_factuur);

      // --- DASHBOARD (altijd leesbaar) ---
      if (request.method === "GET" && path === "/api/dashboard") {
        const { results: invoices } = await env.DB.prepare(
          'SELECT * FROM invoices WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(userId).all();

        let stats = { openstaand: 0, betaaldDitJaar: 0, verlopen: 0, omzetExclBtw: 0, btwTeBetalen: 0 };
        invoices.forEach(inv => {
          if (inv.status === 'Openstaand' || inv.status === 'Offerte') stats.openstaand += inv.total || 0;
          if (inv.status === 'Verlopen') stats.verlopen += inv.total || 0;
          if (inv.status === 'Betaald') {
            stats.betaaldDitJaar += inv.total || 0;
            stats.omzetExclBtw += inv.subtotal || 0;
            stats.btwTeBetalen += inv.vat_total || 0;
          }
        });
        return jsonResponse({ invoices, stats }, 200, request);
      }

      // --- INSTELLINGEN ---
      if (path === "/api/settings") {
        if (request.method === "GET") {
          const settings = await env.DB.prepare('SELECT * FROM user_settings WHERE user_id = ?').bind(userId).first() || {};
          return jsonResponse({ settings }, 200, request);
        }
        if (request.method === "POST") {
          if (!hasFactuurPlan) return DEMO_BLOCKED(request);

          const data = await request.json();
          if (data.logo_base64) {
            const base64Data = data.logo_base64.split(',')[1] || data.logo_base64;
            const approxBytes = base64Data.length * 0.75;
            if (approxBytes > MAX_LOGO_BYTES) {
              return jsonResponse({ error: 'Logo te groot. Maximum is 200KB.' }, 400, request);
            }
          }

          await env.DB.prepare(`
            INSERT INTO user_settings (user_id, company_name, address, zipcode_city, kvk_number, btw_number, iban, logo_base64, brand_color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              company_name=excluded.company_name, address=excluded.address, zipcode_city=excluded.zipcode_city,
              kvk_number=excluded.kvk_number, btw_number=excluded.btw_number, iban=excluded.iban,
              logo_base64=CASE WHEN excluded.logo_base64 IS NOT NULL THEN excluded.logo_base64 ELSE user_settings.logo_base64 END,
              brand_color=excluded.brand_color
          `).bind(
            userId, data.company_name, data.address, data.zipcode_city,
            data.kvk_number, data.btw_number, data.iban,
            data.logo_base64 || null, data.brand_color || '#4f46e5'
          ).run();
          return jsonResponse({ message: 'Instellingen opgeslagen' }, 200, request);
        }
      }

      // --- KLANTEN ---
      if (path === "/api/customers") {
        if (request.method === "GET") {
          const { results } = await env.DB.prepare(
            'SELECT * FROM customers WHERE user_id = ? ORDER BY name ASC'
          ).bind(userId).all();
          return jsonResponse({ customers: results }, 200, request);
        }
        if (request.method === "POST") {
          if (!hasFactuurPlan) return DEMO_BLOCKED(request);
          const data = await request.json();
          if (!data.name?.trim()) return jsonResponse({ error: 'Naam is verplicht' }, 400, request);
          if (!data.address?.trim()) return jsonResponse({ error: 'Adres is verplicht' }, 400, request);
          const id = crypto.randomUUID();
          await env.DB.prepare(
            'INSERT INTO customers (id, user_id, name, address, zipcode_city, kvk_number, btw_number, iban, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(id, userId, data.name.trim(), data.address.trim(),
            data.zipcode_city || null, data.kvk_number || null,
            data.btw_number || null, data.iban || null, data.email || null
          ).run();
          return jsonResponse({ message: 'Klant opgeslagen', id }, 200, request);
        }
      }

      if (path.match(/^\/api\/customers\/[^/]+$/) && request.method === "DELETE") {
        if (!hasFactuurPlan) return DEMO_BLOCKED(request);
        const customerId = path.split("/")[3];
        await env.DB.prepare('DELETE FROM customers WHERE id = ? AND user_id = ?').bind(customerId, userId).run();
        return jsonResponse({ message: 'Klant verwijderd' }, 200, request);
      }

      // --- FACTUUR AANMAKEN ---
      if (request.method === "POST" && path === "/api/invoices") {
        if (!hasFactuurPlan) return DEMO_BLOCKED(request);
        const inv = await request.json();
        const invId = crypto.randomUUID();
        const dueDate = inv.due_date || inv.issue_date;

        await env.DB.prepare(`
          INSERT INTO invoices (
            id, user_id, invoice_number, issue_date, due_date, status,
            customer_name, customer_address, customer_zipcode_city, customer_email, customer_kvk, customer_btw,
            subtotal, vat_total, total, template_id, notes, lines_json
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          invId, userId, inv.invoice_number, inv.issue_date, dueDate, inv.status,
          inv.customer_name, inv.customer_address || null, inv.customer_zipcode_city || null,
          inv.customer_email || null, inv.customer_kvk || null, inv.customer_btw || null,
          inv.subtotal, inv.vat_total, inv.total, inv.template_id,
          inv.notes || null, JSON.stringify(inv.lines || [])
        ).run();
        return jsonResponse({ message: 'Factuur opgeslagen', id: invId }, 200, request);
      }

      // --- FACTUUR STATUS UPDATEN ---
      if (request.method === "PUT" && path.match(/^\/api\/invoices\/[^/]+\/status$/)) {
        if (!hasFactuurPlan) return DEMO_BLOCKED(request);
        const invoiceId = path.split("/")[3];
        const { status } = await request.json();
        const validStatuses = ['Offerte', 'Openstaand', 'Betaald', 'Verlopen'];
        if (!validStatuses.includes(status)) return jsonResponse({ error: 'Ongeldige status' }, 400, request);
        await env.DB.prepare('UPDATE invoices SET status = ? WHERE id = ? AND user_id = ?').bind(status, invoiceId, userId).run();
        return jsonResponse({ message: 'Status aangepast' }, 200, request);
      }

      return jsonResponse({ error: 'Route niet gevonden' }, 404, request);

    } catch (error) {
      return jsonResponse({ error: 'Serverfout: ' + error.message }, 500, request);
    }
  }
};

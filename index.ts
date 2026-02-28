// --- HULPFUNCTIES ---
const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

async function hashPassword(password) {
  const msgUint8 = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendEmail(apiKey, to, subject, html) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'Spectux Portaal <noreply@spectux.com>', 
      to: [to],
      subject: subject,
      html: html
    })
  });
  return res.ok;
}

function getCorsHeaders(request) {
  const allowedOrigins = ['http://localhost:8080', 'http://localhost:5173', 'http://localhost:3000', 'https://spectux.com', 'https://www.spectux.com'];
  const origin = request.headers.get('Origin');
  const isAllowed = allowedOrigins.includes(origin);

  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : allowedOrigins[0] || "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status, request) {
  return new Response(JSON.stringify(body), {
    status: status,
    headers: {
      "Content-Type": "application/json",
      ...getCorsHeaders(request)
    }
  });
}

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
          const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
          if (existingUser) return jsonResponse({ error: 'E-mailadres is al in gebruik' }, 400, request);

          const id = crypto.randomUUID();
          const passwordHash = await hashPassword(password);
          const code = generateCode();
          const expires = new Date(Date.now() + 15 * 60000).toISOString(); 

          await env.DB.prepare(
            `INSERT INTO users (id, name, email, password_hash, verification_code, verification_expires, plan_factuur, plan_planner) VALUES (?, ?, ?, ?, ?, ?, 0, 0)`
          ).bind(id, name, email, passwordHash, code, expires).run();

          await sendEmail(env.RESEND_API_KEY, email, 'Verifieer je account', `<p>Welkom bij Spectux! Je code is: <strong>${code}</strong></p>`);
          return jsonResponse({ message: 'Code verstuurd' }, 200, request);
        }

        if (path === '/api/auth/verify') {
          const { email, code } = await request.json();
          const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(email, code).first();
          if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
          if (new Date(user.verification_expires) < new Date()) return jsonResponse({ error: 'Code is verlopen.' }, 400, request);

          await env.DB.prepare('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(email).run();
          return jsonResponse({ message: 'Account geverifieerd' }, 200, request);
        }

        if (path === '/api/auth/login') {
          const { email, password } = await request.json();
          const passwordHash = await hashPassword(password);
          const user = await env.DB.prepare('SELECT id, name, is_verified, plan_factuur, plan_planner FROM users WHERE email = ? AND password_hash = ?').bind(email, passwordHash).first();

          if (!user) return jsonResponse({ error: 'Ongeldige inloggegevens.' }, 401, request);
          if (user.is_verified === 0) return jsonResponse({ error: 'Account is niet geverifieerd' }, 403, request);

          return jsonResponse({ 
            message: 'Succesvol ingelogd',
            token: user.id, // Simpele token setup voor nu
            user: { id: user.id, name: user.name, plans: { factuur: Boolean(user.plan_factuur), planner: Boolean(user.plan_planner) } }
          }, 200, request);
        }
      }

      // ==========================================
      // 2. PROTECTED ROUTES (Requires Authorization Header)
      // ==========================================
      const authHeader = request.headers.get("Authorization");
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);
      }
      const userId = authHeader.split(" ")[1];

      // --- DASHBOARD & FACTUREN LIJST ---
      if (request.method === "GET" && path === "/api/dashboard") {
        const { results: invoices } = await env.DB.prepare('SELECT * FROM invoices WHERE user_id = ? ORDER BY created_at DESC').bind(userId).all();
        
        let stats = { openstaand: 0, betaaldDitJaar: 0, verlopen: 0, omzetExclBtw: 0, btwTeBetalen: 0 };
        const currentYear = new Date().getFullYear();

        invoices.forEach(inv => {
          if (inv.status === 'Openstaand' || inv.status === 'Concept') stats.openstaand += inv.total;
          if (inv.status === 'Vervallen') stats.verlopen += inv.total;
          if (inv.status === 'Betaald') {
            stats.betaaldDitJaar += inv.total;
            stats.omzetExclBtw += inv.subtotal;
            stats.btwTeBetalen += inv.vat_total;
          }
        });

        return jsonResponse({ invoices, stats }, 200, request);
      }

      // --- BEDRIJFSINSTELLINGEN (Ophalen & Opslaan) ---
      if (path === "/api/settings") {
        if (request.method === "GET") {
          const settings = await env.DB.prepare('SELECT * FROM user_settings WHERE user_id = ?').bind(userId).first() || {};
          return jsonResponse({ settings }, 200, request);
        }
        
        if (request.method === "POST") {
          const data = await request.json();
          await env.DB.prepare(`
            INSERT INTO user_settings (user_id, company_name, address, zipcode_city, kvk_number, btw_number, iban)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET 
            company_name=excluded.company_name, address=excluded.address, zipcode_city=excluded.zipcode_city,
            kvk_number=excluded.kvk_number, btw_number=excluded.btw_number, iban=excluded.iban
          `).bind(userId, data.company_name, data.address, data.zipcode_city, data.kvk_number, data.btw_number, data.iban).run();
          return jsonResponse({ message: "Instellingen opgeslagen" }, 200, request);
        }
      }

      // --- FACTUUR AANMAKEN ---
      if (request.method === "POST" && path === "/api/invoices") {
        const user = await env.DB.prepare('SELECT plan_factuur FROM users WHERE id = ?').bind(userId).first();
        
        // DEMO CHECK
        if (!user.plan_factuur) {
          const { results } = await env.DB.prepare('SELECT count(*) as count FROM invoices WHERE user_id = ?').bind(userId).all();
          if (results[0].count >= 3) {
            return jsonResponse({ error: "Demo limiet bereikt (max 3 facturen). Upgrade je account." }, 403, request);
          }
        }

        const inv = await request.json();
        const invId = crypto.randomUUID();

        await env.DB.prepare(`
          INSERT INTO invoices (id, user_id, invoice_number, issue_date, due_date, status, customer_name, subtotal, vat_total, total, template_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(invId, userId, inv.invoice_number, inv.issue_date, inv.due_date, inv.status, inv.customer_name, inv.subtotal, inv.vat_total, inv.total, inv.template_id).run();

        // Voor het gemak slaan we de factuurregels hier even over in de db opslag voor deze simpele flow, 
        // maar in een echt systeem loop je hier over inv.lines heen en doe je INSERT INTO invoice_lines.

        return jsonResponse({ message: "Factuur succesvol opgeslagen", id: invId }, 200, request);
      }

      // --- FACTUUR STATUS UPDATEN ---
      if (request.method === "PUT" && path.startsWith("/api/invoices/")) {
        const invoiceId = path.split("/").pop(); // Haal ID uit URL
        const { status } = await request.json();
        
        await env.DB.prepare('UPDATE invoices SET status = ? WHERE id = ? AND user_id = ?').bind(status, invoiceId, userId).run();
        return jsonResponse({ message: "Status aangepast" }, 200, request);
      }

      return jsonResponse({ error: 'Route niet gevonden' }, 404, request);

    } catch (error) {
      return jsonResponse({ error: 'Serverfout: ' + error.message }, 500, request);
    }
  }
};

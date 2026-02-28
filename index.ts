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
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Secret",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status, request) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...getCorsHeaders(request) }
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
      // 0. PORTAL ADMIN ROUTES (eigen secret)
      // ==========================================
      if (path.startsWith('/api/portal-admin/')) {
        const adminSecret = (request.headers.get('X-Admin-Secret') || '').trim();
        const expectedSecret = (env.ADMIN_SECRET || '').trim();

        // Tijdelijke debug route — verwijder dit later!
        if (path === '/api/portal-admin/debug') {
          return jsonResponse({
            received_length: adminSecret.length,
            expected_length: expectedSecret.length,
            match: adminSecret === expectedSecret,
            received_first3: adminSecret.substring(0, 3),
            expected_first3: expectedSecret.substring(0, 3),
          }, 200, request);
        }

        if (!adminSecret || adminSecret !== expectedSecret) {
          return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);
        }

        // Alle gebruikers ophalen
        if (path === '/api/portal-admin/users' && request.method === 'GET') {
          const { results: users } = await env.DB.prepare(
            'SELECT id, name, email, is_verified, plan_factuur, plan_planner, created_at FROM users ORDER BY created_at DESC'
          ).all();

          const usersWithStats = await Promise.all(users.map(async (user) => {
            const invoiceCount = await env.DB.prepare('SELECT COUNT(*) as count FROM invoices WHERE user_id = ?').bind(user.id).first();
            const customerCount = await env.DB.prepare('SELECT COUNT(*) as count FROM customers WHERE user_id = ?').bind(user.id).first();
            const totalInvoiced = await env.DB.prepare('SELECT SUM(total) as sum FROM invoices WHERE user_id = ?').bind(user.id).first();
            return {
              ...user,
              invoice_count: invoiceCount?.count || 0,
              customer_count: customerCount?.count || 0,
              total_invoiced: totalInvoiced?.sum || 0,
            };
          }));

          return jsonResponse({ users: usersWithStats }, 200, request);
        }

        // Statistieken
        if (path === '/api/portal-admin/stats' && request.method === 'GET') {
          const userCount = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();
          const verifiedCount = await env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE is_verified = 1').first();
          const premiumCount = await env.DB.prepare('SELECT COUNT(*) as count FROM users WHERE plan_factuur = 1').first();
          const invoiceCount = await env.DB.prepare('SELECT COUNT(*) as count FROM invoices').first();
          const customerCount = await env.DB.prepare('SELECT COUNT(*) as count FROM customers').first();
          const totalRevenue = await env.DB.prepare("SELECT COALESCE(SUM(total), 0) as total FROM invoices WHERE status = 'Betaald'").first();
          const openRevenue = await env.DB.prepare("SELECT COALESCE(SUM(total), 0) as total FROM invoices WHERE status = 'Openstaand'").first();
          const invoicesByStatus = await env.DB.prepare('SELECT status, COUNT(*) as count FROM invoices GROUP BY status').all();

          return jsonResponse({
            users: userCount?.count || 0,
            verified_users: verifiedCount?.count || 0,
            premium_users: premiumCount?.count || 0,
            invoices: invoiceCount?.count || 0,
            customers: customerCount?.count || 0,
            total_revenue_paid: totalRevenue?.total || 0,
            total_revenue_open: openRevenue?.total || 0,
            invoices_by_status: invoicesByStatus?.results || [],
          }, 200, request);
        }

        // Alle facturen ophalen (met gebruikersinfo)
        if (path === '/api/portal-admin/invoices' && request.method === 'GET') {
          const { results: invoices } = await env.DB.prepare(
            `SELECT i.id, i.invoice_number, i.issue_date, i.status, i.customer_name, i.total, i.subtotal, i.vat_total,
                    u.name as user_name, u.email as user_email
             FROM invoices i
             JOIN users u ON i.user_id = u.id
             ORDER BY i.created_at DESC LIMIT 200`
          ).all();
          return jsonResponse({ invoices }, 200, request);
        }

        // Premium toggle
        if (path.match(/^\/api\/portal-admin\/users\/[^/]+\/toggle-premium$/) && request.method === 'POST') {
          const userId = path.split('/')[4];
          const { plan_factuur } = await request.json();
          await env.DB.prepare('UPDATE users SET plan_factuur = ? WHERE id = ?').bind(plan_factuur ? 1 : 0, userId).run();
          return jsonResponse({ message: 'Plan bijgewerkt' }, 200, request);
        }

        // Gebruiker verwijderen (incl. alle data)
        if (path.match(/^\/api\/portal-admin\/users\/[^/]+$/) && request.method === 'DELETE') {
          const userId = path.split('/')[4];
          await env.DB.prepare('DELETE FROM invoices WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM customers WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM user_settings WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
          return jsonResponse({ message: 'Gebruiker en alle data verwijderd' }, 200, request);
        }

        return jsonResponse({ error: 'Admin route niet gevonden' }, 404, request);
      }

      // ==========================================
      // 1. PUBLIC AUTH ROUTES
      // ==========================================
      if (path.startsWith('/api/auth/')) {
        if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405, request);

        if (path === '/api/auth/register') {
          const { name, email, password } = await request.json();
          // FIX: E-mail altijd lowercase opslaan
          const normalizedEmail = email.toLowerCase().trim();

          const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
          if (existing) return jsonResponse({ error: 'E-mailadres is al in gebruik' }, 400, request);

          const id = crypto.randomUUID();
          const passwordHash = await hashPassword(password);
          const code = generateCode();
          const expires = new Date(Date.now() + 15 * 60000).toISOString();

          await env.DB.prepare(
            'INSERT INTO users (id, name, email, password_hash, verification_code, verification_expires, plan_factuur, plan_planner) VALUES (?, ?, ?, ?, ?, ?, 0, 0)'
          ).bind(id, name, normalizedEmail, passwordHash, code, expires).run();

          await sendEmail(env.RESEND_API_KEY, normalizedEmail, 'Verifieer je Spectux account',
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
          // FIX: E-mail normaliseren
          const normalizedEmail = email.toLowerCase().trim();

          const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(normalizedEmail, code).first();
          if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
          if (new Date(user.verification_expires) < new Date()) return jsonResponse({ error: 'Code is verlopen' }, 400, request);
          await env.DB.prepare('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(normalizedEmail).run();
          return jsonResponse({ message: 'Account geverifieerd' }, 200, request);
        }

        if (path === '/api/auth/login') {
          const { email, password } = await request.json();
          // FIX: E-mail altijd lowercase voor vergelijking
          const normalizedEmail = email.toLowerCase().trim();
          const passwordHash = await hashPassword(password);

          const user = await env.DB.prepare(
            'SELECT id, name, is_verified, plan_factuur, plan_planner FROM users WHERE email = ? AND password_hash = ?'
          ).bind(normalizedEmail, passwordHash).first();

          if (!user) return jsonResponse({ error: 'Ongeldige inloggegevens' }, 401, request);
          if (user.is_verified === 0) return jsonResponse({ error: 'Account is niet geverifieerd' }, 403, request);

          return jsonResponse({
            message: 'Succesvol ingelogd',
            token: user.id,
            user: { id: user.id, name: user.name, plans: { factuur: Boolean(user.plan_factuur), planner: Boolean(user.plan_planner) } }
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

      const userRecord = await env.DB.prepare('SELECT id, plan_factuur FROM users WHERE id = ?').bind(userId).first();
      if (!userRecord) return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);

      // --- DASHBOARD ---
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
          const data = await request.json();
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
          const data = await request.json();
          if (!data.name?.trim()) return jsonResponse({ error: 'Naam is verplicht' }, 400, request);
          if (!data.address?.trim()) return jsonResponse({ error: 'Adres is verplicht' }, 400, request);

          const id = crypto.randomUUID();
          await env.DB.prepare(
            'INSERT INTO customers (id, user_id, name, address, zipcode_city, kvk_number, btw_number, iban, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(
            id, userId, data.name.trim(), data.address.trim(),
            data.zipcode_city || null, data.kvk_number || null,
            data.btw_number || null, data.iban || null, data.email || null
          ).run();
          return jsonResponse({ message: 'Klant opgeslagen', id }, 200, request);
        }
      }

      if (path.match(/^\/api\/customers\/[^/]+$/) && request.method === "DELETE") {
        const customerId = path.split("/")[3];
        await env.DB.prepare('DELETE FROM customers WHERE id = ? AND user_id = ?').bind(customerId, userId).run();
        return jsonResponse({ message: 'Klant verwijderd' }, 200, request);
      }

      // --- FACTUUR AANMAKEN ---
      if (request.method === "POST" && path === "/api/invoices") {
        if (!userRecord.plan_factuur) {
          const countResult = await env.DB.prepare('SELECT COUNT(*) as count FROM invoices WHERE user_id = ?').bind(userId).first();
          if ((countResult?.count || 0) >= 3) {
            return jsonResponse({ error: 'Demo limiet bereikt (max 3 facturen). Upgrade je account.' }, 403, request);
          }
        }

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

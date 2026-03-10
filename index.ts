// ==========================================
// SPECTUX PORTAAL WORKER — v3
// ==========================================
// Nieuw in v3:
//   POST/GET/DELETE /api/planner/services
//   POST/GET/DELETE /api/planner/staff
//   POST/GET/DELETE /api/planner/appointments
//   PUT             /api/planner/appointments/:id/status
//   POST/GET/DELETE /api/planner/timeslots
//   GET/PUT         /api/planner/settings
//   GET             /api/planner/google/auth-url  (stub)
//   POST            /api/planner/google/disconnect
//   DELETE          /api/invoices/:id
//   GET             /api/invoices/:id
//   PUT             /api/invoices/:id   (bewerken)
//   scheduled       → verwijdert planner data ouder dan 10 dagen
// ==========================================

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
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Secret, X-Internal-Secret",
    "Access-Control-Max-Age": "86400",
  };
}

function jsonResponse(body, status, request) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...getCorsHeaders(request) }
  });
}

export default {
  // ──────────────────────────────────────────────
  // SCHEDULED: elke dag om 03:00 UTC
  // Verwijdert planner data ouder dan 10 dagen
  // Voeg in wrangler.toml toe:
  //   [triggers]
  //   crons = ["0 3 * * *"]
  // ──────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 10);
    const cutoffStr = cutoff.toISOString().split('T')[0];
    try {
      await env.DB.prepare('DELETE FROM planner_appointments WHERE datum < ?').bind(cutoffStr).run();
      await env.DB.prepare('DELETE FROM planner_timeslots WHERE datum < ?').bind(cutoffStr).run();
      console.log(`[cleanup] Verwijderd planner data vóór ${cutoffStr}`);
    } catch (e) {
      console.error('[cleanup] Fout:', e.message);
    }
  },

  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: getCorsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {

      // ==========================================
      // 0. PORTAL ADMIN ROUTES
      // ==========================================
      if (path.startsWith('/api/portal-admin/')) {
        const authHeader = request.headers.get('Authorization') || '';
        const adminSecret = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
        const expectedSecret = (env.ADMIN_SECRET || '').trim();

        if (!adminSecret || adminSecret !== expectedSecret) {
          return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);
        }

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

        if (path.match(/^\/api\/portal-admin\/users\/[^/]+\/toggle-premium$/) && request.method === 'POST') {
          const userId = path.split('/')[4];
          const { plan_factuur } = await request.json();
          await env.DB.prepare('UPDATE users SET plan_factuur = ? WHERE id = ?').bind(plan_factuur ? 1 : 0, userId).run();
          return jsonResponse({ message: 'Plan bijgewerkt' }, 200, request);
        }

        if (path.match(/^\/api\/portal-admin\/users\/[^/]+\/toggle-planner$/) && request.method === 'POST') {
          const userId = path.split('/')[4];
          const { plan_planner } = await request.json();
          await env.DB.prepare('UPDATE users SET plan_planner = ? WHERE id = ?').bind(plan_planner ? 1 : 0, userId).run();
          return jsonResponse({ message: 'Planner plan bijgewerkt' }, 200, request);
        }

        if (path === '/api/portal-admin/planner-stats' && request.method === 'GET') {
          const totalServices     = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_services').first();
          const totalStaff        = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_staff').first();
          const totalAppointments = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_appointments').first();
          const totalTimeslots    = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_timeslots').first();
          const plannerPremium    = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE plan_planner = 1').first();
          const activeToday       = await env.DB.prepare("SELECT COUNT(*) as c FROM planner_appointments WHERE datum = date('now') AND status = 'bevestigd'").first();
          const thisWeek          = await env.DB.prepare("SELECT COUNT(*) as c FROM planner_appointments WHERE datum >= date('now') AND datum <= date('now','+7 days')").first();
          const byStatus          = await env.DB.prepare("SELECT status, COUNT(*) as count FROM planner_appointments GROUP BY status").all();
          const topUsers          = await env.DB.prepare(`
            SELECT u.id, u.name, u.email, u.plan_planner,
              (SELECT COUNT(*) FROM planner_appointments a WHERE a.user_id = u.id) as appt_count,
              (SELECT COUNT(*) FROM planner_services s WHERE s.user_id = u.id) as service_count,
              (SELECT COUNT(*) FROM planner_staff st WHERE st.user_id = u.id) as staff_count,
              (SELECT publieke_url_slug FROM planner_settings ps WHERE ps.user_id = u.id) as slug
            FROM users u
            WHERE u.plan_planner = 1 OR (SELECT COUNT(*) FROM planner_services WHERE user_id = u.id) > 0
            ORDER BY appt_count DESC
            LIMIT 20
          `).all();

          return jsonResponse({
            total_services:      totalServices?.c || 0,
            total_staff:         totalStaff?.c || 0,
            total_appointments:  totalAppointments?.c || 0,
            total_timeslots:     totalTimeslots?.c || 0,
            planner_premium:     plannerPremium?.c || 0,
            active_today:        activeToday?.c || 0,
            this_week:           thisWeek?.c || 0,
            by_status:           byStatus?.results || [],
            top_users:           topUsers?.results || [],
          }, 200, request);
        }

        if (path.match(/^\/api\/portal-admin\/users\/[^/]+$/) && request.method === 'DELETE') {
          const userId = path.split('/')[4];
          await env.DB.prepare('DELETE FROM invoices WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM customers WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM user_settings WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_appointments WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_timeslots WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_services WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_staff WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_availabilities WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM planner_settings WHERE user_id = ?').bind(userId).run();
          await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
          return jsonResponse({ message: 'Gebruiker en alle data verwijderd' }, 200, request);
        }

        return jsonResponse({ error: 'Admin route niet gevonden' }, 404, request);
      }

      // ==========================================
      // INTERN ENDPOINT
      // ==========================================
      if (path === '/api/internal/activate-plan' && request.method === 'POST') {
        const internalSecret = request.headers.get('X-Internal-Secret') || '';
        if (!internalSecret || internalSecret !== (env.INTERNAL_SECRET || '')) {
          return jsonResponse({ error: 'Intern endpoint: toegang geweigerd' }, 401, request);
        }

        const { email, name, password_hash, is_new_user, plan } = await request.json();
        const normalizedEmail = email.toLowerCase().trim();

        const existingUser = await env.DB.prepare('SELECT id, plan_factuur FROM users WHERE email = ?').bind(normalizedEmail).first();

        if (existingUser) {
          await env.DB.prepare('UPDATE users SET plan_factuur = 1 WHERE id = ?').bind(existingUser.id).run();
          await sendEmail(
            env.RESEND_API_KEY, normalizedEmail, 'Spectux Factuur Tool geactiveerd!',
            `<div style="font-family:sans-serif;max-width:520px;margin:auto;color:#333">
              <h2 style="color:#4f46e5">Factuur Tool geactiveerd 🎉</h2>
              <p>Je Spectux Factuur Tool is geactiveerd!</p>
              <a href="https://spectux.com/portaal" style="display:inline-block;background:#4f46e5;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:12px 0">Open Portaal</a>
              <p style="color:#888;font-size:13px">Vragen? Mail ons op info@spectux.com</p>
            </div>`
          );
          return jsonResponse({ message: 'Plan geactiveerd voor bestaand account', user_id: existingUser.id }, 200, request);
        } else {
          if (!password_hash || !name) {
            return jsonResponse({ error: 'name en password_hash vereist voor nieuw account' }, 400, request);
          }
          const newId = crypto.randomUUID();
          await env.DB.prepare(
            `INSERT INTO users (id, name, email, password_hash, is_verified, plan_factuur, plan_planner) VALUES (?, ?, ?, ?, 1, 1, 0)`
          ).bind(newId, name.trim(), normalizedEmail, password_hash).run();
          await sendEmail(
            env.RESEND_API_KEY, normalizedEmail, 'Welkom bij Spectux — jouw account is klaar!',
            `<div style="font-family:sans-serif;max-width:520px;margin:auto;color:#333">
              <h2 style="color:#4f46e5">Welkom bij Spectux, ${name}! 🎉</h2>
              <p>Je abonnement is actief en je Factuur Tool account staat klaar.</p>
              <a href="https://spectux.com/portaal" style="display:inline-block;background:#4f46e5;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:12px 0">Inloggen bij Spectux Portaal</a>
              <p><strong>E-mail:</strong> ${normalizedEmail}</p>
              <p style="color:#888;font-size:13px">Vragen? Mail ons op info@spectux.com</p>
            </div>`
          );
          return jsonResponse({ message: 'Nieuw account aangemaakt en plan geactiveerd', user_id: newId }, 200, request);
        }
      }

      // ==========================================
      // 1. PUBLIC AUTH ROUTES
      // ==========================================
      if (path.startsWith('/api/auth/')) {

        if (path === '/api/auth/check-email' && request.method === 'POST') {
          const { email } = await request.json();
          const normalizedEmail = email.toLowerCase().trim();
          const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
          return jsonResponse({ exists: !!existing }, 200, request);
        }

        if (request.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405, request);

        if (path === '/api/auth/register') {
          const { name, email, password } = await request.json();
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
          const normalizedEmail = email.toLowerCase().trim();
          const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(normalizedEmail, code).first();
          if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
          if (new Date(user.verification_expires) < new Date()) return jsonResponse({ error: 'Code is verlopen' }, 400, request);
          await env.DB.prepare('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(normalizedEmail).run();
          return jsonResponse({ message: 'Account geverifieerd' }, 200, request);
        }

        if (path === '/api/auth/login') {
          const { email, password } = await request.json();
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
      // PUBLIC BOOKING ROUTES (geen auth vereist)
      // Gebruikt door spectux.com/booking/[slug]
      // ==========================================
      if (path.startsWith('/api/public/booking/')) {
        const parts = path.split('/'); // ['','api','public','booking',slug,...rest]
        const slug  = parts[4];
        const sub   = parts[5]; // 'availability' | undefined

        if (!slug) return jsonResponse({ error: 'Geen slug opgegeven' }, 400, request);

        // Zoek user op basis van slug
        const settings = await env.DB.prepare(
          'SELECT * FROM planner_settings WHERE publieke_url_slug = ?'
        ).bind(slug).first();

        if (!settings) return jsonResponse({ error: 'Boekingspagina niet gevonden' }, 404, request);

        const userId = settings.user_id;

        // Check of user premium planner heeft
        const user = await env.DB.prepare('SELECT plan_planner FROM users WHERE id = ?').bind(userId).first();
        if (!user?.plan_planner) {
          return jsonResponse({ error: 'Deze boekingspagina is niet actief.' }, 403, request);
        }

        // ── GET /api/public/booking/:slug — info + diensten + medewerkers ──
// ── GET /api/public/booking/:slug — info + diensten + medewerkers ──
        if (!sub && request.method === 'GET') {
          const { results: services } = await env.DB.prepare(
            'SELECT id, naam, duur_in_minuten, prijs, kleur, beschrijving FROM planner_services WHERE user_id = ? ORDER BY naam ASC'
          ).bind(userId).all();

          const { results: staff } = await env.DB.prepare(
            'SELECT id, naam, functie, kleur FROM planner_staff WHERE user_id = ? ORDER BY naam ASC'
          ).bind(userId).all();

          const { results: availabilities } = await env.DB.prepare(
            'SELECT dag_van_de_week, start_tijd, eind_tijd, is_beschikbaar FROM planner_availabilities WHERE user_id = ? ORDER BY dag_van_de_week ASC'
          ).bind(userId).all();

          // Nieuw: Haal ook de bezette tijden op voor de kalender
          const { results: booked_slots } = await env.DB.prepare(
            "SELECT datum, start_tijd, eind_tijd, staff_id FROM planner_appointments WHERE user_id = ? AND status != 'geannuleerd' AND datum >= date('now')"
          ).bind(userId).all();

          return jsonResponse({
            settings: { // <-- Netjes verpakt in 'settings' zoals React verwacht
              bedrijfs_naam:         settings.bedrijfs_naam || '',
              bedrijfs_beschrijving: settings.bedrijfs_beschrijving || '',
              slot_interval:         settings.slot_interval || 15,
              max_days_vooruit:      settings.max_days_vooruit || 30,
              availability_mode:     settings.availability_mode || 'recurring',
            },
            slug: settings.publieke_url_slug,
            is_premium: Boolean(user.plan_planner), // <-- Voeg is_premium toe
            services,
            staff,
            availabilities,
            booked_slots, // <-- Voeg bezette slots toe
          }, 200, request);
        }

        // ── GET /api/public/booking/:slug/availability?datum=YYYY-MM-DD ──
        // Geeft beschikbare tijdsloten terug op een specifieke datum
        if (sub === 'availability' && request.method === 'GET') {
          const datum = url.searchParams.get('datum');
          const serviceId = url.searchParams.get('service_id');
          if (!datum) return jsonResponse({ error: 'datum parameter vereist' }, 400, request);

          // Duur van de dienst ophalen
          let duur = settings.slot_interval || 15;
          if (serviceId) {
            const svc = await env.DB.prepare('SELECT duur_in_minuten FROM planner_services WHERE id = ? AND user_id = ?').bind(serviceId, userId).first();
            if (svc) duur = svc.duur_in_minuten;
          }

          // Bestaande afspraken op die datum
          const { results: bestaandeAfspraken } = await env.DB.prepare(
            "SELECT start_tijd, eind_tijd FROM planner_appointments WHERE user_id = ? AND datum = ? AND status != 'geannuleerd'"
          ).bind(userId, datum).all();

          const bezet = bestaandeAfspraken.map(a => ({ start: a.start_tijd, eind: a.eind_tijd }));

          // Helper: minuten naar "HH:MM"
          const minToTime = (m) => `${String(Math.floor(m/60)).padStart(2,'0')}:${String(m%60).padStart(2,'0')}`;
          const timeToMin = (t) => { const [h,m] = t.split(':').map(Number); return h*60+m; };
          const overlaps = (startA, eindA, startB, eindB) => startA < eindB && eindA > startB;

          let windows = []; // [{van: minutes, tot: minutes}]

          if (settings.availability_mode === 'custom_slots') {
            // Gebruik tijdsloten uit DB voor deze datum
            const { results: slots } = await env.DB.prepare(
              'SELECT start_tijd, eind_tijd FROM planner_timeslots WHERE user_id = ? AND datum = ? ORDER BY start_tijd ASC'
            ).bind(userId, datum).all();
            windows = slots.map(s => ({ van: timeToMin(s.start_tijd), tot: timeToMin(s.eind_tijd) }));
          } else {
            // Terugkerend patroon: kijk welke dag van de week
            const dayOfWeek = (new Date(datum).getDay() + 6) % 7; // 0=ma, 6=zo
            const { results: avails } = await env.DB.prepare(
              'SELECT start_tijd, eind_tijd, is_beschikbaar FROM planner_availabilities WHERE user_id = ? AND dag_van_de_week = ?'
            ).bind(userId, dayOfWeek).all();
            for (const a of avails) {
              if (a.is_beschikbaar) windows.push({ van: timeToMin(a.start_tijd), tot: timeToMin(a.eind_tijd) });
            }
          }

          // Genereer slots per slot_interval, filter bezette
          const interval = settings.slot_interval || 15;
          const beschikbaar = [];

          for (const w of windows) {
            let cur = w.van;
            while (cur + duur <= w.tot) {
              const slotEnd = cur + duur;
              const slotStart_str = minToTime(cur);
              const slotEnd_str   = minToTime(slotEnd);
              const isBezet = bezet.some(b => overlaps(cur, slotEnd, timeToMin(b.start), timeToMin(b.eind)));
              if (!isBezet) beschikbaar.push({ start_tijd: slotStart_str, eind_tijd: slotEnd_str });
              cur += interval;
            }
          }

          return jsonResponse({ datum, slots: beschikbaar }, 200, request);
        }

        // ── POST /api/public/booking/:slug — nieuwe afspraak aanmaken ──
        if (!sub && request.method === 'POST') {
          const body = await request.json();
          const { service_id, staff_id, klant_naam, klant_email, klant_telefoon, datum, start_tijd, notitie } = body;

          if (!service_id || !klant_naam || !klant_email || !datum || !start_tijd) {
            return jsonResponse({ error: 'Vul alle verplichte velden in (dienst, naam, email, datum, tijd)' }, 400, request);
          }

          // Dienst ophalen
          const svc = await env.DB.prepare('SELECT * FROM planner_services WHERE id = ? AND user_id = ?').bind(service_id, userId).first();
          if (!svc) return jsonResponse({ error: 'Dienst niet gevonden' }, 404, request);

          // Eindtijd berekenen
          const [h, m] = start_tijd.split(':').map(Number);
          const endMin  = h * 60 + m + svc.duur_in_minuten;
          const eind_tijd = `${String(Math.floor(endMin/60)).padStart(2,'0')}:${String(endMin%60).padStart(2,'0')}`;

          // Check of slot al bezet is
          const conflict = await env.DB.prepare(
            "SELECT id FROM planner_appointments WHERE user_id=? AND datum=? AND status!='geannuleerd' AND start_tijd < ? AND eind_tijd > ?"
          ).bind(userId, datum, eind_tijd, start_tijd).first();
          if (conflict) return jsonResponse({ error: 'Dit tijdstip is helaas al bezet. Kies een ander tijdslot.' }, 409, request);

          // Medewerker info
          let staff_naam = '';
          if (staff_id) {
            const stf = await env.DB.prepare('SELECT naam FROM planner_staff WHERE id = ? AND user_id = ?').bind(staff_id, userId).first();
            if (stf) staff_naam = stf.naam;
          }

          const id = crypto.randomUUID();
          const cancellation_token = crypto.randomUUID();

          await env.DB.prepare(`
            INSERT INTO planner_appointments
              (id, user_id, service_id, staff_id, klant_naam, klant_email, klant_telefoon,
               datum, start_tijd, eind_tijd, service_naam, service_kleur, staff_naam,
               status, notitie, cancellation_token, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'bevestigd',?,?,datetime('now'))
          `).bind(
            id, userId, service_id, staff_id || null,
            klant_naam, klant_email, klant_telefoon || null,
            datum, start_tijd, eind_tijd,
            svc.naam, svc.kleur, staff_naam,
            notitie || null, cancellation_token
          ).run();

          // Bevestigingsmail naar klant
          if (env.RESEND_API_KEY) {
            const datumNL = new Date(datum).toLocaleDateString('nl-NL', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
            await sendEmail(
              env.RESEND_API_KEY,
              klant_email,
              `Afspraakbevestiging — ${svc.naam} bij ${settings.bedrijfs_naam || 'Spectux'}`,
              `<h2>Je afspraak is bevestigd! ✅</h2>
              <p>Hoi ${klant_naam},</p>
              <p>Je afspraak staat gepland:</p>
              <ul>
                <li><strong>Dienst:</strong> ${svc.naam}</li>
                ${staff_naam ? `<li><strong>Medewerker:</strong> ${staff_naam}</li>` : ''}
                <li><strong>Datum:</strong> ${datumNL}</li>
                <li><strong>Tijd:</strong> ${start_tijd} – ${eind_tijd}</li>
                <li><strong>Locatie:</strong> ${settings.bedrijfs_naam || ''}</li>
              </ul>
              <p>Wil je annuleren? <a href="https://spectux.com/booking/${slug}/cancel/${cancellation_token}">Klik hier om te annuleren</a>.</p>
              <p>Tot dan!<br/>${settings.bedrijfs_naam || 'Spectux'}</p>`
            );
          }

          return jsonResponse({
            success: true,
            id,
            cancellation_token,
            afspraak: { datum, start_tijd, eind_tijd, service_naam: svc.naam, staff_naam },
          }, 201, request);
        }

        // ── GET /api/public/booking/:slug/cancel/:token — afspraak annuleren ──
        if (sub === 'cancel' && request.method === 'POST') {
          const token = parts[6];
          if (!token) return jsonResponse({ error: 'Geen token' }, 400, request);
          const appt = await env.DB.prepare(
            "SELECT id, klant_naam, datum, start_tijd, service_naam FROM planner_appointments WHERE cancellation_token = ? AND user_id = ?"
          ).bind(token, userId).first();
          if (!appt) return jsonResponse({ error: 'Afspraak niet gevonden of al geannuleerd' }, 404, request);
          await env.DB.prepare(
            "UPDATE planner_appointments SET status = 'geannuleerd' WHERE cancellation_token = ?"
          ).bind(token).run();
          return jsonResponse({ success: true, message: `Afspraak van ${appt.klant_naam} op ${appt.datum} om ${appt.start_tijd} is geannuleerd.` }, 200, request);
        }

        return jsonResponse({ error: 'Route niet gevonden' }, 404, request);
      }

      // ==========================================
      // 2. PROTECTED ROUTES (Beveiliging / Authenticated)
      // ==========================================
      const authHeader = request.headers.get("Authorization");
      if (!authHeader?.startsWith("Bearer ")) {
        return jsonResponse({ error: 'Niet geautoriseerd' }, 401, request);
      }
      const userId = authHeader.split(" ")[1];

      const userRecord = await env.DB.prepare('SELECT id, plan_factuur, plan_planner FROM users WHERE id = ?').bind(userId).first();
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
          const { results } = await env.DB.prepare('SELECT * FROM customers WHERE user_id = ? ORDER BY name ASC').bind(userId).all();
          return jsonResponse({ customers: results }, 200, request);
        }
        if (request.method === "POST") {
          const data = await request.json();
          if (!data.name?.trim()) return jsonResponse({ error: 'Naam is verplicht' }, 400, request);
          if (!data.address?.trim()) return jsonResponse({ error: 'Adres is verplicht' }, 400, request);
          const id = crypto.randomUUID();
          await env.DB.prepare(
            'INSERT INTO customers (id, user_id, name, address, zipcode_city, kvk_number, btw_number, iban, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(id, userId, data.name.trim(), data.address.trim(), data.zipcode_city || null, data.kvk_number || null, data.btw_number || null, data.iban || null, data.email || null).run();
          return jsonResponse({ message: 'Klant opgeslagen', id }, 200, request);
        }
      }

      if (path.match(/^\/api\/customers\/[^/]+$/) && request.method === "DELETE") {
        const customerId = path.split("/")[3];
        await env.DB.prepare('DELETE FROM customers WHERE id = ? AND user_id = ?').bind(customerId, userId).run();
        return jsonResponse({ message: 'Klant verwijderd' }, 200, request);
      }

      // ==========================================
      // --- FACTUREN ---
      // ==========================================

      // Lijst / aanmaken
      if (path === "/api/invoices") {
        if (request.method === "POST") {
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
            INSERT INTO invoices (id, user_id, invoice_number, issue_date, due_date, status,
              customer_name, customer_address, customer_zipcode_city, customer_email, customer_kvk, customer_btw,
              subtotal, vat_total, total, template_id, notes, lines_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            invId, userId, inv.invoice_number, inv.issue_date, dueDate, inv.status,
            inv.customer_name, inv.customer_address || null, inv.customer_zipcode_city || null,
            inv.customer_email || null, inv.customer_kvk || null, inv.customer_btw || null,
            inv.subtotal, inv.vat_total, inv.total, inv.template_id,
            inv.notes || null, JSON.stringify(inv.lines || [])
          ).run();
          return jsonResponse({ message: 'Factuur opgeslagen', id: invId }, 200, request);
        }
      }

      // Enkelvoudige factuur — lezen, bewerken, verwijderen
      if (path.match(/^\/api\/invoices\/[^/]+$/) && !path.endsWith('/status')) {
        const invoiceId = path.split("/")[3];

        if (request.method === "GET") {
          const inv = await env.DB.prepare('SELECT * FROM invoices WHERE id = ? AND user_id = ?').bind(invoiceId, userId).first();
          if (!inv) return jsonResponse({ error: 'Factuur niet gevonden' }, 404, request);
          return jsonResponse({ invoice: { ...inv, lines: JSON.parse(inv.lines_json || '[]') } }, 200, request);
        }

        if (request.method === "PUT") {
          if (!userRecord.plan_factuur) {
            return jsonResponse({ error: 'Premium vereist om facturen te bewerken.' }, 403, request);
          }
          const inv = await request.json();
          const dueDate = inv.due_date || inv.issue_date;
          await env.DB.prepare(`
            UPDATE invoices SET
              invoice_number=?, issue_date=?, due_date=?, status=?,
              customer_name=?, customer_address=?, customer_zipcode_city=?, customer_email=?, customer_kvk=?, customer_btw=?,
              subtotal=?, vat_total=?, total=?, template_id=?, notes=?, lines_json=?
            WHERE id=? AND user_id=?
          `).bind(
            inv.invoice_number, inv.issue_date, dueDate, inv.status,
            inv.customer_name, inv.customer_address || null, inv.customer_zipcode_city || null,
            inv.customer_email || null, inv.customer_kvk || null, inv.customer_btw || null,
            inv.subtotal, inv.vat_total, inv.total, inv.template_id,
            inv.notes || null, JSON.stringify(inv.lines || []),
            invoiceId, userId
          ).run();
          return jsonResponse({ message: 'Factuur bijgewerkt' }, 200, request);
        }

        if (request.method === "DELETE") {
          if (!userRecord.plan_factuur) {
            return jsonResponse({ error: 'Premium vereist om facturen te verwijderen.' }, 403, request);
          }
          await env.DB.prepare('DELETE FROM invoices WHERE id = ? AND user_id = ?').bind(invoiceId, userId).run();
          return jsonResponse({ message: 'Factuur verwijderd' }, 200, request);
        }
      }

      // Status updaten
      if (request.method === "PUT" && path.match(/^\/api\/invoices\/[^/]+\/status$/)) {
        const invoiceId = path.split("/")[3];
        const { status } = await request.json();
        const validStatuses = ['Offerte', 'Openstaand', 'Betaald', 'Verlopen'];
        if (!validStatuses.includes(status)) return jsonResponse({ error: 'Ongeldige status' }, 400, request);
        await env.DB.prepare('UPDATE invoices SET status = ? WHERE id = ? AND user_id = ?').bind(status, invoiceId, userId).run();
        return jsonResponse({ message: 'Status aangepast' }, 200, request);
      }

      // ==========================================
      // 3. PLANNER ROUTES (Protected by Auth)
      // ==========================================
      if (path.startsWith('/api/planner/')) {
        const isPlannerPremium = Boolean(userRecord.plan_planner);

        // ── SERVICES ──────────────────────────────────────────────
        if (path === '/api/planner/services') {
          if (request.method === 'GET') {
            const { results } = await env.DB.prepare(
              'SELECT * FROM planner_services WHERE user_id = ? ORDER BY naam ASC'
            ).bind(userId).all();
            return jsonResponse({ services: results }, 200, request);
          }
          if (request.method === 'POST') {
            const data = await request.json();
            if (!data.naam?.trim()) return jsonResponse({ error: 'Naam is verplicht' }, 400, request);
            // Gratis: max 1 dienst
            if (!isPlannerPremium) {
              const count = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_services WHERE user_id = ?').bind(userId).first();
              if ((count?.c || 0) >= 1) return jsonResponse({ error: 'Max 1 dienst op gratis account.', upgrade: true }, 403, request);
            }
            const id = crypto.randomUUID();
            await env.DB.prepare(
              'INSERT INTO planner_services (id, user_id, naam, duur_in_minuten, prijs, kleur, beschrijving) VALUES (?, ?, ?, ?, ?, ?, ?)'
            ).bind(id, userId, data.naam.trim(), data.duur_in_minuten || 60, data.prijs || 0, data.kleur || '#4f46e5', data.beschrijving || null).run();
            return jsonResponse({ message: 'Dienst opgeslagen', id }, 200, request);
          }
        }

        if (path.match(/^\/api\/planner\/services\/[^/]+$/) && request.method === 'DELETE') {
          const id = path.split('/')[4];
          await env.DB.prepare('DELETE FROM planner_services WHERE id = ? AND user_id = ?').bind(id, userId).run();
          return jsonResponse({ message: 'Dienst verwijderd' }, 200, request);
        }

        // ── STAFF ─────────────────────────────────────────────────
        if (path === '/api/planner/staff') {
          if (request.method === 'GET') {
            const { results } = await env.DB.prepare(
              'SELECT * FROM planner_staff WHERE user_id = ? ORDER BY naam ASC'
            ).bind(userId).all();
            return jsonResponse({ staff: results }, 200, request);
          }
          if (request.method === 'POST') {
            const data = await request.json();
            if (!data.naam?.trim()) return jsonResponse({ error: 'Naam is verplicht' }, 400, request);
            if (!isPlannerPremium) {
              const count = await env.DB.prepare('SELECT COUNT(*) as c FROM planner_staff WHERE user_id = ?').bind(userId).first();
              if ((count?.c || 0) >= 1) return jsonResponse({ error: 'Max 1 medewerker op gratis account.', upgrade: true }, 403, request);
            }
            const id = crypto.randomUUID();
            await env.DB.prepare(
              'INSERT INTO planner_staff (id, user_id, naam, functie, kleur) VALUES (?, ?, ?, ?, ?)'
            ).bind(id, userId, data.naam.trim(), data.functie || null, data.kleur || '#06b6d4').run();
            return jsonResponse({ message: 'Medewerker toegevoegd', id }, 200, request);
          }
        }

        if (path.match(/^\/api\/planner\/staff\/[^/]+$/) && request.method === 'DELETE') {
          const id = path.split('/')[4];
          await env.DB.prepare('DELETE FROM planner_staff WHERE id = ? AND user_id = ?').bind(id, userId).run();
          return jsonResponse({ message: 'Medewerker verwijderd' }, 200, request);
        }

        // ── APPOINTMENTS ──────────────────────────────────────────
        if (path === '/api/planner/appointments') {
          if (request.method === 'GET') {
            const van = url.searchParams.get('van') || new Date().toISOString().split('T')[0];
            const tot = url.searchParams.get('tot') || van;
            const { results } = await env.DB.prepare(
              'SELECT * FROM planner_appointments WHERE user_id = ? AND datum >= ? AND datum <= ? ORDER BY datum ASC, start_tijd ASC'
            ).bind(userId, van, tot).all();
            return jsonResponse({ appointments: results }, 200, request);
          }
          if (request.method === 'POST') {
            const data = await request.json();
            if (!data.service_id || !data.klant_naam?.trim() || !data.datum || !data.start_tijd) {
              return jsonResponse({ error: 'service_id, klant_naam, datum en start_tijd zijn verplicht' }, 400, request);
            }
            // Bereken eind_tijd op basis van service duur
            const svc = await env.DB.prepare('SELECT duur_in_minuten, naam, kleur FROM planner_services WHERE id = ? AND user_id = ?').bind(data.service_id, userId).first();
            const stf = data.staff_id ? await env.DB.prepare('SELECT naam FROM planner_staff WHERE id = ? AND user_id = ?').bind(data.staff_id, userId).first() : null;
            const [h, m] = (data.start_tijd || '09:00').split(':').map(Number);
            const endMin = h * 60 + m + (svc?.duur_in_minuten || 60);
            const eind_tijd = `${String(Math.floor(endMin / 60)).padStart(2, '0')}:${String(endMin % 60).padStart(2, '0')}`;
            const id = crypto.randomUUID();
            const token = crypto.randomUUID();
            await env.DB.prepare(`
              INSERT INTO planner_appointments
                (id, user_id, service_id, staff_id, klant_naam, klant_email, klant_telefoon, datum, start_tijd, eind_tijd,
                 service_naam, service_kleur, staff_naam, status, notitie, cancellation_token)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'bevestigd', ?, ?)
            `).bind(
              id, userId, data.service_id, data.staff_id || null,
              data.klant_naam.trim(), data.klant_email || null, data.klant_telefoon || null,
              data.datum, data.start_tijd, eind_tijd,
              svc?.naam || '', svc?.kleur || '#4f46e5', stf?.naam || null,
              data.notitie || null, token
            ).run();
            return jsonResponse({ message: 'Afspraak toegevoegd', id }, 200, request);
          }
        }

        if (path.match(/^\/api\/planner\/appointments\/[^/]+$/) && request.method === 'DELETE') {
          const id = path.split('/')[4];
          await env.DB.prepare('DELETE FROM planner_appointments WHERE id = ? AND user_id = ?').bind(id, userId).run();
          return jsonResponse({ message: 'Afspraak verwijderd' }, 200, request);
        }

        if (path.match(/^\/api\/planner\/appointments\/[^/]+\/status$/) && request.method === 'PUT') {
          const id = path.split('/')[4];
          const { status } = await request.json();
          const valid = ['bevestigd', 'geannuleerd', 'no-show', 'voltooid'];
          if (!valid.includes(status)) return jsonResponse({ error: 'Ongeldige status' }, 400, request);
          await env.DB.prepare('UPDATE planner_appointments SET status = ? WHERE id = ? AND user_id = ?').bind(status, id, userId).run();
          return jsonResponse({ message: 'Status bijgewerkt' }, 200, request);
        }

        // ── TIMESLOTS ─────────────────────────────────────────────
        if (path === '/api/planner/timeslots') {
          if (request.method === 'GET') {
            const van = url.searchParams.get('van') || new Date().toISOString().split('T')[0];
            const tot = url.searchParams.get('tot') || van;
            const { results } = await env.DB.prepare(
              'SELECT * FROM planner_timeslots WHERE user_id = ? AND datum >= ? AND datum <= ? ORDER BY datum ASC, start_tijd ASC'
            ).bind(userId, van, tot).all();
            return jsonResponse({ slots: results }, 200, request);
          }
          if (request.method === 'POST') {
            const data = await request.json();
            if (!data.datum || !data.start_tijd || !data.eind_tijd) {
              return jsonResponse({ error: 'datum, start_tijd en eind_tijd zijn verplicht' }, 400, request);
            }
            if (data.start_tijd >= data.eind_tijd) {
              return jsonResponse({ error: 'Starttijd moet vóór eindtijd liggen' }, 400, request);
            }
            const id = crypto.randomUUID();
            await env.DB.prepare(
              'INSERT INTO planner_timeslots (id, user_id, datum, start_tijd, eind_tijd, staff_id) VALUES (?, ?, ?, ?, ?, ?)'
            ).bind(id, userId, data.datum, data.start_tijd, data.eind_tijd, data.staff_id || null).run();
            return jsonResponse({ message: 'Tijdslot toegevoegd', id }, 200, request);
          }
        }

        if (path.match(/^\/api\/planner\/timeslots\/[^/]+$/) && request.method === 'DELETE') {
          const id = path.split('/')[4];
          await env.DB.prepare('DELETE FROM planner_timeslots WHERE id = ? AND user_id = ?').bind(id, userId).run();
          return jsonResponse({ message: 'Tijdslot verwijderd' }, 200, request);
        }

        // ── SETTINGS ──────────────────────────────────────────────
        if (path === '/api/planner/settings') {
          if (request.method === 'GET') {
            const settings = await env.DB.prepare('SELECT * FROM planner_settings WHERE user_id = ?').bind(userId).first() || {};
            const { results: availabilities } = await env.DB.prepare(
              'SELECT * FROM planner_availabilities WHERE user_id = ? ORDER BY dag_van_de_week ASC'
            ).bind(userId).all();
            return jsonResponse({ settings, availabilities }, 200, request);
          }
          if (request.method === 'PUT') {
            const data = await request.json();
            if (!data.publieke_url_slug?.trim()) {
              return jsonResponse({ error: 'URL slug is verplicht' }, 400, request);
            }
            // Slug uniciteit controleren (andere users)
            const slugCheck = await env.DB.prepare(
              'SELECT user_id FROM planner_settings WHERE publieke_url_slug = ? AND user_id != ?'
            ).bind(data.publieke_url_slug.trim(), userId).first();
            if (slugCheck) return jsonResponse({ error: 'Deze URL slug is al in gebruik' }, 409, request);

            await env.DB.prepare(`
              INSERT INTO planner_settings
                (user_id, publieke_url_slug, bedrijfs_naam, bedrijfs_beschrijving, slot_interval, availability_mode, max_days_vooruit, google_calendar_enabled)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
              ON CONFLICT(user_id) DO UPDATE SET
                publieke_url_slug=excluded.publieke_url_slug,
                bedrijfs_naam=excluded.bedrijfs_naam,
                bedrijfs_beschrijving=excluded.bedrijfs_beschrijving,
                slot_interval=excluded.slot_interval,
                availability_mode=excluded.availability_mode,
                max_days_vooruit=excluded.max_days_vooruit
            `).bind(
              userId, data.publieke_url_slug.trim(), data.bedrijfs_naam || null,
              data.bedrijfs_beschrijving || null, data.slot_interval || 15,
              data.availability_mode || 'recurring', data.max_days_vooruit || 30,
              data.google_calendar_enabled ? 1 : 0
            ).run();

            // Beschikbaarheden opslaan
            if (Array.isArray(data.availabilities)) {
              await env.DB.prepare('DELETE FROM planner_availabilities WHERE user_id = ?').bind(userId).run();
              for (const avail of data.availabilities) {
                await env.DB.prepare(
                  'INSERT INTO planner_availabilities (id, user_id, dag_van_de_week, start_tijd, eind_tijd, is_beschikbaar) VALUES (?, ?, ?, ?, ?, ?)'
                ).bind(crypto.randomUUID(), userId, avail.dag_van_de_week, avail.start_tijd, avail.eind_tijd, avail.is_beschikbaar ? 1 : 0).run();
              }
            }

            return jsonResponse({ message: 'Planner instellingen opgeslagen' }, 200, request);
          }
        }

        // ── GOOGLE CALENDAR (stub) ────────────────────────────────
        if (path === '/api/planner/google/auth-url' && request.method === 'GET') {
          if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET) {
            return jsonResponse({ error: 'Google Calendar is niet geconfigureerd op deze server.' }, 501, request);
          }
          const redirectUri = `${url.origin}/api/planner/google/callback`;
          const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${env.GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=https://www.googleapis.com/auth/calendar&access_type=offline&prompt=consent&state=${userId}`;
          return jsonResponse({ auth_url: authUrl }, 200, request);
        }

        if (path === '/api/planner/google/disconnect' && request.method === 'POST') {
          await env.DB.prepare(
            'UPDATE planner_settings SET google_calendar_enabled=0, google_access_token=NULL, google_refresh_token=NULL WHERE user_id=?'
          ).bind(userId).run();
          return jsonResponse({ message: 'Google Calendar ontkoppeld' }, 200, request);
        }

        return jsonResponse({ error: 'Planner route niet gevonden' }, 404, request);
      }

      return jsonResponse({ error: 'Route niet gevonden' }, 404, request);

    } catch (error) {
      return jsonResponse({ error: 'Serverfout: ' + error.message }, 500, request);
    }
  }
};

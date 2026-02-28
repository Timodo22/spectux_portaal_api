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

// --- CORS & RESPONSE HELPER ---
function getCorsHeaders(request) {
  const allowedOrigins = ['http://localhost:8080', 'http://localhost:5173', 'http://localhost:3000', 'https://spectux.com', 'https://www.spectux.com'];
  const origin = request.headers.get('Origin');
  const isAllowed = allowedOrigins.includes(origin);

  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : allowedOrigins[0],
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "600",
    "Access-Control-Allow-Credentials": "true"
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
    // 1. Handel CORS Preflight (OPTIONS) af
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: getCorsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    // Alleen POST requests toestaan voor onze auth routes
    if (request.method !== "POST") {
      return jsonResponse({ error: "Method not allowed" }, 405, request);
    }

    try {
      // --- ROUTE: INLOGGEN MET GOOGLE ---
      if (path === '/api/auth/google') {
        const { token } = await request.json();

        // 1. Verifieer het token bij Google
        const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
        if (!googleRes.ok) return jsonResponse({ error: 'Ongeldig Google token' }, 401, request);
        
        const googleUser = await googleRes.json();
        const { sub: googleId, email, name, email_verified } = googleUser;

        if (email_verified !== "true") {
          return jsonResponse({ error: 'Google e-mailadres is niet geverifieerd' }, 403, request);
        }

        // 2. Kijk of de gebruiker al bestaat in jouw database
        let user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

        if (user) {
          // Gebruiker bestaat. Koppel Google ID als dit nog niet is gebeurd.
          if (!user.google_id) {
            await env.DB.prepare('UPDATE users SET google_id = ?, provider = ?, is_verified = 1 WHERE email = ?')
              .bind(googleId, 'google', email).run();
          }
        } else {
          // 3. Maak een nieuwe gebruiker aan als deze niet bestaat
          const id = crypto.randomUUID();
          await env.DB.prepare(
            `INSERT INTO users (id, name, email, provider, google_id, is_verified) VALUES (?, ?, ?, ?, ?, ?)`
          ).bind(id, name, email, 'google', googleId, 1).run(); // is_verified is direct 1
          
          user = await env.DB.prepare('SELECT id, name, plan_factuur, plan_planner FROM users WHERE email = ?').bind(email).first();
        }

        // 4. Stuur succes response terug
        return jsonResponse({ 
          message: 'Succesvol ingelogd met Google',
          user: {
            id: user.id,
            name: user.name,
            plans: { factuur: Boolean(user.plan_factuur), planner: Boolean(user.plan_planner) }
          }
        }, 200, request);
      }

      // --- ROUTE: REGISTREREN ---
      if (path === '/api/auth/register') {
        const { name, email, password } = await request.json();
        
        const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existingUser) return jsonResponse({ error: 'E-mailadres is al in gebruik' }, 400, request);

        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);
        const code = generateCode();
        const expires = new Date(Date.now() + 15 * 60000).toISOString(); 

        await env.DB.prepare(
          `INSERT INTO users (id, name, email, password_hash, verification_code, verification_expires, provider) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, name, email, passwordHash, code, expires, 'local').run();

        const emailSent = await sendEmail(env.RESEND_API_KEY, email, 'Verifieer je account', `<p>Welkom bij Spectux! Je verificatiecode is: <strong>${code}</strong></p>`);
        
        if (!emailSent) return jsonResponse({ error: 'Kon e-mail niet versturen' }, 500, request);
        return jsonResponse({ message: 'Code verstuurd' }, 200, request);
      }

      // --- ROUTE: VERIFIEER EMAIL ---
      if (path === '/api/auth/verify') {
        const { email, code } = await request.json();
        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(email, code).first();

        if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
        if (new Date(user.verification_expires) < new Date()) {
          return jsonResponse({ error: 'Code is verlopen. Vraag een nieuwe aan.' }, 400, request);
        }

        await env.DB.prepare('UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(email).run();
        return jsonResponse({ message: 'Account succesvol geverifieerd' }, 200, request);
      }

      // --- ROUTE: INLOGGEN ---
      if (path === '/api/auth/login') {
        const { email, password } = await request.json();
        const passwordHash = await hashPassword(password);

        const user = await env.DB.prepare(
          'SELECT id, name, is_verified, plan_factuur, plan_planner FROM users WHERE email = ? AND password_hash = ?'
        ).bind(email, passwordHash).first();

        if (!user) return jsonResponse({ error: 'Ongeldige inloggegevens. Log je misschien in via Google?' }, 401, request);
        if (user.is_verified === 0) return jsonResponse({ error: 'Account is nog niet geverifieerd' }, 403, request);

        return jsonResponse({ 
          message: 'Succesvol ingelogd',
          user: {
            id: user.id,
            name: user.name,
            plans: { factuur: Boolean(user.plan_factuur), planner: Boolean(user.plan_planner) }
          }
        }, 200, request);
      }

      // --- ROUTE: WACHTWOORD RESET CODE AANVRAGEN ---
      if (path === '/api/auth/forgot-password') {
        const { email } = await request.json();
        
        const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (!user) return jsonResponse({ message: 'Als dit e-mailadres bestaat, is er een code gestuurd.' }, 200, request);

        const code = generateCode();
        const expires = new Date(Date.now() + 15 * 60000).toISOString();

        await env.DB.prepare('UPDATE users SET verification_code = ?, verification_expires = ? WHERE email = ?').bind(code, expires, email).run();
        await sendEmail(env.RESEND_API_KEY, email, 'Wachtwoord herstellen', `<p>Je code om je wachtwoord te herstellen is: <strong>${code}</strong></p>`);

        return jsonResponse({ message: 'Code verstuurd' }, 200, request);
      }

      // --- ROUTE: NIEUW WACHTWOORD INSTELLEN ---
      if (path === '/api/auth/reset-password') {
        const { email, code, newPassword } = await request.json();

        const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND verification_code = ?').bind(email, code).first();

        if (!user) return jsonResponse({ error: 'Ongeldige code' }, 400, request);
        if (new Date(user.verification_expires) < new Date()) {
          return jsonResponse({ error: 'Code is verlopen' }, 400, request);
        }

        const passwordHash = await hashPassword(newPassword);
        await env.DB.prepare('UPDATE users SET password_hash = ?, verification_code = NULL, verification_expires = NULL WHERE email = ?').bind(passwordHash, email).run();

        return jsonResponse({ message: 'Wachtwoord succesvol gewijzigd' }, 200, request);
      }

      // Als de route niet wordt herkend:
      return jsonResponse({ error: 'Route niet gevonden' }, 404, request);

    } catch (error) {
      return jsonResponse({ error: 'Interne serverfout: ' + error.message }, 500, request);
    }
  }
};

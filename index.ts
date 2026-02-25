import { Hono } from 'hono'
import { cors } from 'hono/cors'

// Defineer de bindings (Environment variables & D1)
type Bindings = {
  DB: D1Database
  RESEND_API_KEY: string
}

const app = new Hono<{ Bindings: Bindings }>()

// Zet CORS open voor je frontend (aangepast naar .com)
app.use('/*', cors({
  origin: ['http://localhost:5173', 'https://spectux.com', 'https://www.spectux.com'], 
  allowHeaders: ['Content-Type', 'Authorization'],
  allowMethods: ['POST', 'GET', 'OPTIONS'],
  maxAge: 600,
  credentials: true,
}))

// --- HULPFUNCTIES ---

const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString()

async function hashPassword(password: string) {
  const msgUint8 = new TextEncoder().encode(password)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

async function sendEmail(apiKey: string, to: string, subject: string, html: string) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'Spectux Portaal <noreply@spectux.com>', // Aangepast naar .com
      to: [to],
      subject: subject,
      html: html
    })
  })
  return res.ok
}

// --- API ROUTES ---

app.post('/api/auth/register', async (c) => {
  const { name, email, password } = await c.req.json()
  
  const existingUser = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (existingUser) return c.json({ error: 'E-mailadres is al in gebruik' }, 400)

  const id = crypto.randomUUID()
  const passwordHash = await hashPassword(password)
  const code = generateCode()
  const expires = new Date(Date.now() + 15 * 60000).toISOString() // 15 min geldig

  await c.env.DB.prepare(
    `INSERT INTO users (id, name, email, password_hash, verification_code, verification_expires) 
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, name, email, passwordHash, code, expires).run()

  const emailSent = await sendEmail(
    c.env.RESEND_API_KEY, 
    email, 
    'Verifieer je account', 
    `<p>Welkom bij Spectux! Je verificatiecode is: <strong>${code}</strong></p>`
  )

  if (!emailSent) return c.json({ error: 'Kon e-mail niet versturen' }, 500)
  return c.json({ message: 'Code verstuurd' })
})

app.post('/api/auth/verify', async (c) => {
  const { email, code } = await c.req.json()

  const user = await c.env.DB.prepare(
    'SELECT * FROM users WHERE email = ? AND verification_code = ?'
  ).bind(email, code).first()

  if (!user) return c.json({ error: 'Ongeldige code' }, 400)
  if (new Date(user.verification_expires as string) < new Date()) {
    return c.json({ error: 'Code is verlopen. Vraag een nieuwe aan.' }, 400)
  }

  await c.env.DB.prepare(
    'UPDATE users SET is_verified = 1, verification_code = NULL, verification_expires = NULL WHERE email = ?'
  ).bind(email).run()

  return c.json({ message: 'Account succesvol geverifieerd' })
})

app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json()
  const passwordHash = await hashPassword(password)

  const user = await c.env.DB.prepare(
    'SELECT id, name, is_verified, plan_factuur, plan_planner FROM users WHERE email = ? AND password_hash = ?'
  ).bind(email, passwordHash).first()

  if (!user) return c.json({ error: 'Ongeldige inloggegevens' }, 401)
  if (user.is_verified === 0) return c.json({ error: 'Account is nog niet geverifieerd' }, 403)

  return c.json({ 
    message: 'Succesvol ingelogd',
    user: {
      id: user.id,
      name: user.name,
      plans: {
        factuur: Boolean(user.plan_factuur),
        planner: Boolean(user.plan_planner)
      }
    }
  })
})

app.post('/api/auth/forgot-password', async (c) => {
  const { email } = await c.req.json()
  
  const user = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (!user) return c.json({ message: 'Als dit e-mailadres bestaat, is er een code gestuurd.' })

  const code = generateCode()
  const expires = new Date(Date.now() + 15 * 60000).toISOString()

  await c.env.DB.prepare(
    'UPDATE users SET verification_code = ?, verification_expires = ? WHERE email = ?'
  ).bind(code, expires, email).run()

  await sendEmail(
    c.env.RESEND_API_KEY, 
    email, 
    'Wachtwoord herstellen', 
    `<p>Je code om je wachtwoord te herstellen is: <strong>${code}</strong></p>`
  )

  return c.json({ message: 'Code verstuurd' })
})

app.post('/api/auth/reset-password', async (c) => {
  const { email, code, newPassword } = await c.req.json()

  const user = await c.env.DB.prepare(
    'SELECT * FROM users WHERE email = ? AND verification_code = ?'
  ).bind(email, code).first()

  if (!user) return c.json({ error: 'Ongeldige code' }, 400)
  if (new Date(user.verification_expires as string) < new Date()) {
    return c.json({ error: 'Code is verlopen' }, 400)
  }

  const passwordHash = await hashPassword(newPassword)

  await c.env.DB.prepare(
    'UPDATE users SET password_hash = ?, verification_code = NULL, verification_expires = NULL WHERE email = ?'
  ).bind(passwordHash, email).run()

  return c.json({ message: 'Wachtwoord succesvol gewijzigd' })
})

export default app

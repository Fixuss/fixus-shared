// auth.js — fixus-auth (sumado al paquete fixus-afip en la Etapa 3 del plan
// de unificación: login único con rol, contraseña por usuario).
//
// Vive en el mismo repo/paquete que la integración AFIP para no multiplicar
// repos chicos — se usa igual, como import nombrado desde 'fixus-afip'. Dos
// partes, sin dependencias nuevas (todo con el módulo "crypto" nativo de
// Node, disponible en runtime Node de Next.js — no usar desde un API route
// con `runtime: 'edge'`):
//
//   1. Hashing de contraseñas — scrypt + salt, formato de guardado "salt:hash".
//   2. Token de sesión firmado (HMAC-SHA256, estilo JWT simplificado) con un
//      secreto compartido (AUTH_SECRET) — así el Portal puede "pasarle" una
//      sesión válida a cualquier otra app por URL (?sesion=<token>) sin que
//      viaje ninguna contraseña ni se necesite un backend de sesión central.
//
// Uso típico — login (donde se verifica la contraseña, ej. fixus-cobros):
//
//   import { verifyPassword, signSession } from 'fixus-afip'
//   const ok = await verifyPassword(passwordIngresada, usuario.passwordHash)
//   if (ok) {
//     const token = signSession({ id: usuario.id, nombre: usuario.nombre, rol: usuario.rol }, process.env.AUTH_SECRET)
//     // devolver `token` al Portal, que lo agrega como ?sesion=<token> al link de cada app
//   }
//
// Uso típico — recibir la sesión en cualquier otra app (ej. tablero-fixus):
//
//   import { verifySession } from 'fixus-afip'
//   const payload = verifySession(req.query.sesion, process.env.AUTH_SECRET)
//   if (payload) { /* setear cookie propia httpOnly con el payload, redirigir sin el query param */ }

import crypto from 'crypto'

const TTL_SESION_SEGUNDOS = 60 * 60 * 12 // 12hs — se renueva cada vez que se vuelve a entrar por el Portal

export class SessionError extends Error {}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err)
      else resolve(derivedKey.toString('hex'))
    })
  })
}

export async function hashPassword(password) {
  if (!password || password.length < 4) {
    throw new SessionError('La contraseña debe tener al menos 4 caracteres')
  }
  const salt = crypto.randomBytes(16).toString('hex')
  const hash = await scryptAsync(password, salt)
  return `${salt}:${hash}`
}

export async function verifyPassword(password, stored) {
  if (!password || !stored || !stored.includes(':')) return false
  const [salt, hash] = stored.split(':')
  const check = await scryptAsync(password, salt)
  const a = Buffer.from(hash, 'hex')
  const b = Buffer.from(check, 'hex')
  if (a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

function base64url(input) {
  return Buffer.from(input).toString('base64url')
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(a)
  const bufB = Buffer.from(b)
  if (bufA.length !== bufB.length) return false
  return crypto.timingSafeEqual(bufA, bufB)
}

// payload sugerido: { id, nombre, inicial, rol }
export function signSession(payload, secret, ttlSeconds = TTL_SESION_SEGUNDOS) {
  if (!secret) throw new SessionError('Falta AUTH_SECRET')
  const body = { ...payload, exp: Date.now() + ttlSeconds * 1000 }
  const data = base64url(JSON.stringify(body))
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url')
  return `${data}.${sig}`
}

// Devuelve el payload si el token es válido y no venció, o null.
export function verifySession(token, secret) {
  if (!token || !secret) return null
  const partes = token.split('.')
  if (partes.length !== 2) return null
  const [data, sig] = partes
  const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url')
  if (!timingSafeEqualStr(sig, expected)) return null
  try {
    const body = JSON.parse(Buffer.from(data, 'base64url').toString())
    if (!body.exp || Date.now() > body.exp) return null
    return body
  } catch {
    return null
  }
}

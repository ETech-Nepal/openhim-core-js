'use strict'

// RFC 9449 DPoP proof verification. Only used when the access token is
// sender-constrained (carries cnf.jkt) and authentication.jwt.dpopPublicBaseUrl is set.

import jwt from 'jsonwebtoken'
import {createHash, createPublicKey} from 'crypto'

const ASYMMETRIC_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA'
]
const MAX_SKEW_SECONDS = 300
const REPLAY_CACHE_LIMIT = 10000

// RFC 7638: only the required public members, lexicographically ordered
const THUMBPRINT_MEMBERS = {
  RSA: ['e', 'kty', 'n'],
  EC: ['crv', 'kty', 'x', 'y'],
  OKP: ['crv', 'kty', 'x']
}

// ponytail: in-process jti replay cache; move to a shared store if core is scaled out.
const seenJti = new Map()

export function jwkThumbprint(jwk) {
  const members = THUMBPRINT_MEMBERS[jwk.kty]
  if (!members) {
    throw new Error('Malformed DPoP proof')
  }
  const canonical = {}
  for (const m of members) {
    canonical[m] = jwk[m]
  }
  return createHash('sha256')
    .update(JSON.stringify(canonical))
    .digest('base64url')
}

export async function verifyDpop({proof, accessToken, jkt, method, url}) {
  if (!proof) {
    throw new Error('DPoP proof required')
  }

  const decoded = jwt.decode(proof, {complete: true})
  const header = decoded && decoded.header
  if (
    !header ||
    header.typ !== 'dpop+jwt' ||
    !header.jwk ||
    !ASYMMETRIC_ALGS.includes(header.alg)
  ) {
    throw new Error('Malformed DPoP proof')
  }

  let claims
  try {
    const key = createPublicKey({key: header.jwk, format: 'jwk'})
    claims = jwt.verify(proof, key, {algorithms: [header.alg]})
  } catch (err) {
    throw new Error('DPoP signature invalid')
  }

  if (jwkThumbprint(header.jwk) !== jkt) {
    throw new Error('DPoP key does not match token')
  }

  const now = Math.floor(Date.now() / 1000)
  if (!claims.iat || Math.abs(now - claims.iat) > MAX_SKEW_SECONDS) {
    throw new Error('DPoP proof expired')
  }
  if (claims.htm !== method) {
    throw new Error('DPoP htm mismatch')
  }
  if (claims.htu !== url) {
    throw new Error('DPoP htu mismatch')
  }
  const ath = createHash('sha256').update(accessToken).digest('base64url')
  if (claims.ath !== ath) {
    throw new Error('DPoP ath mismatch')
  }
  if (!claims.jti || seenJti.has(claims.jti)) {
    throw new Error('DPoP proof replayed')
  }

  seenJti.set(claims.jti, now)
  if (seenJti.size > REPLAY_CACHE_LIMIT) {
    for (const [id, at] of seenJti) {
      if (now - at > MAX_SKEW_SECONDS) {
        seenJti.delete(id)
      }
    }
  }
}

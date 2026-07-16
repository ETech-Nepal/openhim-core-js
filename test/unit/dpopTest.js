'use strict'

/* eslint-env mocha */

import should from 'should'
import jwt from 'jsonwebtoken'
import {createHash, generateKeyPairSync} from 'crypto'

import {verifyDpop, jwkThumbprint} from '../../src/dpop'

const ACCESS_TOKEN = 'access.token.value'
const URL = 'https://hie.example.org/fhir/Patient'

function makeKey() {
  const {publicKey, privateKey} = generateKeyPairSync('ec', {
    namedCurve: 'P-256'
  })
  const jwk = publicKey.export({format: 'jwk'})
  return {jwk, privateKey, jkt: jwkThumbprint(jwk)}
}

function makeProof(key, claims = {}, header = {}) {
  const payload = {
    jti: Math.random().toString(36).slice(2),
    htm: 'GET',
    htu: URL,
    iat: Math.floor(Date.now() / 1000),
    ath: createHash('sha256').update(ACCESS_TOKEN).digest('base64url'),
    ...claims
  }
  return jwt.sign(payload, key.privateKey, {
    algorithm: 'ES256',
    header: {typ: 'dpop+jwt', jwk: key.jwk, ...header}
  })
}

function verify(key, proof) {
  return verifyDpop({
    proof,
    accessToken: ACCESS_TOKEN,
    jkt: key.jkt,
    method: 'GET',
    url: URL
  })
}

describe('DPoP proof verification', () => {
  it('should accept a valid proof', async () => {
    const key = makeKey()
    await verify(key, makeProof(key))
  })

  it('should reject a missing proof', async () => {
    const key = makeKey()
    await verify(key, undefined).should.be.rejectedWith('DPoP proof required')
  })

  it('should reject a proof without dpop+jwt typ', async () => {
    const key = makeKey()
    await verify(key, makeProof(key, {}, {typ: 'JWT'})).should.be.rejectedWith(
      'Malformed DPoP proof'
    )
  })

  it('should reject a proof signed with a symmetric alg', async () => {
    const key = makeKey()
    const proof = jwt.sign({htm: 'GET'}, 'secret', {
      algorithm: 'HS256',
      header: {typ: 'dpop+jwt', jwk: key.jwk}
    })
    await verify(key, proof).should.be.rejectedWith('Malformed DPoP proof')
  })

  it('should reject a proof whose signature does not match its jwk', async () => {
    const key = makeKey()
    const other = makeKey()
    const proof = makeProof(other, {}, {jwk: key.jwk})
    await verify(key, proof).should.be.rejectedWith('DPoP signature invalid')
  })

  it('should reject a proof whose key does not match the token cnf.jkt', async () => {
    const key = makeKey()
    const other = makeKey()
    await verify(key, makeProof(other)).should.be.rejectedWith(
      'DPoP key does not match token'
    )
  })

  it('should reject an expired proof', async () => {
    const key = makeKey()
    const iat = Math.floor(Date.now() / 1000) - 600
    await verify(key, makeProof(key, {iat})).should.be.rejectedWith(
      'DPoP proof expired'
    )
  })

  it('should reject an htm mismatch', async () => {
    const key = makeKey()
    await verify(key, makeProof(key, {htm: 'POST'})).should.be.rejectedWith(
      'DPoP htm mismatch'
    )
  })

  it('should reject an htu mismatch', async () => {
    const key = makeKey()
    await verify(
      key,
      makeProof(key, {htu: 'https://evil.example.org/fhir/Patient'})
    ).should.be.rejectedWith('DPoP htu mismatch')
  })

  it('should reject an ath mismatch', async () => {
    const key = makeKey()
    await verify(key, makeProof(key, {ath: 'nope'})).should.be.rejectedWith(
      'DPoP ath mismatch'
    )
  })

  it('should reject a replayed jti', async () => {
    const key = makeKey()
    const proof = makeProof(key, {jti: 'fixed-jti'})
    await verify(key, proof)
    await verify(key, proof).should.be.rejectedWith('DPoP proof replayed')
  })

  it('should compute the RFC 7638 thumbprint', () => {
    // Example key from RFC 7638 section 3.1
    const jwk = {
      kty: 'RSA',
      n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
      alg: 'RS256',
      kid: '2011-04-29'
    }
    should(jwkThumbprint(jwk)).eql(
      'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'
    )
  })
})

/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function expandIPv6 (ip: string): string[] | null {
  let address = ip.toLowerCase()
  
  if (address.includes('.')) {
    const lastColon = address.lastIndexOf(':')
    if (lastColon === -1) return null
    const ipv4 = address.slice(lastColon + 1)
    const parts = ipv4.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) return null
    const h1 = ((parts[0] << 8) + parts[1]).toString(16).padStart(4, '0')
    const h2 = ((parts[2] << 8) + parts[3]).toString(16).padStart(4, '0')
    address = address.slice(0, lastColon + 1) + `${h1}:${h2}`
  }

  const parts = address.split(':')
  if (parts.length > 8) return null

  let expandedParts: string[] = []
  const emptyIndex = parts.indexOf('')

  if (emptyIndex !== -1) {
    let cleanParts = [...parts]
    if (cleanParts[0] === '' && cleanParts[1] === '') {
      cleanParts.shift()
    } else if (cleanParts[cleanParts.length - 1] === '' && cleanParts[cleanParts.length - 2] === '') {
      cleanParts.pop()
    }
    
    const countEmpty = 8 - (cleanParts.length - 1)
    const firstEmptyIndex = cleanParts.indexOf('')
    const left = cleanParts.slice(0, firstEmptyIndex)
    const right = cleanParts.slice(firstEmptyIndex + 1)
    const middle = Array(countEmpty).fill('0000')
    expandedParts = [...left, ...middle, ...right]
  } else {
    expandedParts = parts
  }

  if (expandedParts.length !== 8) return null

  return expandedParts.map(part => part.padStart(4, '0'))
}

function isPrivateOrLoopbackIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(isNaN)) {
    return true
  }
  const [p1, p2, p3, p4] = parts

  if (p1 === 127) return true
  if (p1 === 10) return true
  if (p1 === 172 && p2 >= 16 && p2 <= 31) return true
  if (p1 === 192 && p2 === 168) return true
  if (p1 === 169 && p2 === 254) return true
  if (p1 === 0 && p2 === 0 && p3 === 0 && p4 === 0) return true
  if (p1 === 255 && p2 === 255 && p3 === 255 && p4 === 255) return true

  return false
}

function isPrivateOrLoopbackIPv6 (ip: string): boolean {
  const parts = expandIPv6(ip)
  if (!parts) return true

  const isLoopback = parts.slice(0, 7).every(p => p === '0000') && parts[7] === '0001'
  if (isLoopback) return true

  const isUnspecified = parts.every(p => p === '0000')
  if (isUnspecified) return true

  const isIPv4Mapped = parts.slice(0, 5).every(p => p === '0000') && (parts[5] === 'ffff' || parts[5] === '0000')
  if (isIPv4Mapped) {
    const high = parseInt(parts[6], 16)
    const low = parseInt(parts[7], 16)
    if (!isNaN(high) && !isNaN(low)) {
      const p1 = (high >> 8) & 0xff
      const p2 = high & 0xff
      const p3 = (low >> 8) & 0xff
      const p4 = low & 0xff
      return isPrivateOrLoopbackIPv4(`${p1}.${p2}.${p3}.${p4}`)
    }
  }

  const firstGroup = parts[0]
  const firstByte = parseInt(firstGroup.slice(0, 2), 16)
  if (!isNaN(firstByte)) {
    if ((firstByte >> 1) === 0x7e) return true
    const firstThreeHex = firstGroup.slice(0, 3)
    if (['fe8', 'fe9', 'fea', 'feb'].includes(firstThreeHex)) return true
  }

  return false
}

function isPrivateOrLoopbackIp (ip: string): boolean {
  if (net.isIPv4(ip)) {
    return isPrivateOrLoopbackIPv4(ip)
  }
  if (net.isIPv6(ip)) {
    return isPrivateOrLoopbackIPv6(ip)
  }
  return true
}

async function resolveHostname (hostname: string): Promise<string[]> {
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true })
    return addresses.map(addr => addr.address)
  } catch {
    return []
  }
}

async function isSafeUrl (urlStr: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlStr)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '')
    const lowerHost = hostname.toLowerCase()

    if (lowerHost === 'localhost' || lowerHost === 'localhost.localdomain' || lowerHost.endsWith('.local')) {
      return false
    }

    if (net.isIP(hostname)) {
      return !isPrivateOrLoopbackIp(hostname)
    }

    const ips = await resolveHostname(hostname)
    if (ips.length === 0) {
      return false
    }

    for (const ip of ips) {
      if (isPrivateOrLoopbackIp(ip)) {
        return false
      }
    }

    return true
  } catch {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          if (!(await isSafeUrl(url))) {
            throw new Error('Forking/fetching local/private addresses is prohibited to prevent SSRF')
          }
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}

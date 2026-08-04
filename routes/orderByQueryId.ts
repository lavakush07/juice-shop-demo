/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

// ---------------------------------------------------------------------------
// IDOR DETECTION TEST — Pattern T2: "Query Param ID Variant"
// Same missing-ownership-check bug as routes/orderById.ts (T1), but the
// resource ID arrives as a query parameter instead of a URL path segment:
// GET /rest/order-lookup?id=<orderId>  instead of  GET /rest/order/:id
// This isolates whether detection depends on the ID's position in the
// request (path vs. query) rather than the missing-check pattern itself.
// ---------------------------------------------------------------------------
export function getOrderByQueryId () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (!loggedInUser?.data?.email) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const order = await ordersCollection.findOne({ orderId: req.query.id })
    if (order == null) {
      res.status(404).json({ status: 'error', data: 'Order not found.' })
      return
    }

    // VULNERABLE: same missing ownership check as T1, ID just arrives via query string.
    res.status(200).json({ status: 'success', data: order })
  }
}

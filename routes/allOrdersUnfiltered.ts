/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

// ---------------------------------------------------------------------------
// IDOR DETECTION TEST — Pattern T4: "List Endpoint, No Owner Filter"
// A list endpoint that returns EVERY order in the collection, with no
// filter by the requesting user's ownership at all. This is the most
// blatant variant of the pattern - no per-object lookup, no ID juggling,
// just an unfiltered bulk read. If a detector can catch anything in this
// family, this is the version most likely to trip a simple heuristic
// ("query result returned to an HTTP response with no WHERE/filter tied
// to the authenticated user").
// ---------------------------------------------------------------------------
export function getAllOrdersUnfiltered () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (!loggedInUser?.data?.email) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // VULNERABLE: returns every order in the database, not scoped to the caller.
    const allOrders = await ordersCollection.find({})
    res.status(200).json({ status: 'success', data: allOrders })
  }
}

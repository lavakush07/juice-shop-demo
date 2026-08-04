/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

// Lookup a saved order by ID supplied as a query parameter.
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

    res.status(200).json({ status: 'success', data: order })
  }
}

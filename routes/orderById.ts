/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

// ---------------------------------------------------------------------------
// DEMO ENDPOINT — Forrester Wave: Agentic Development Security Tools, Q4 2026
// AI SAST criterion 1a — "Developer persona" scenario.
//
// Returns a saved order by its object ID taken directly from the URL.
// Intentionally OMITS the ownership check (compare order.email to the
// authenticated caller's email) that the equivalent chatbot tool
// (routes/chat.ts -> getOrderById) performs correctly. Any authenticated
// user can therefore retrieve any other user's order by guessing or
// enumerating orderId values — a textbook BOLA / IDOR (OWASP API1:2023).
// ---------------------------------------------------------------------------
export function getOrderById () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (!loggedInUser?.data?.email) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    const order = await ordersCollection.findOne({ orderId: req.params.id })
    if (order == null) {
      res.status(404).json({ status: 'error', data: 'Order not found.' })
      return
    }

    // VULNERABLE: no check that `order.email` matches `loggedInUser.data.email`.
    // Compare to routes/chat.ts getOrderById, which correctly rejects the
    // request when `order.email !== maskedEmail`.
    res.status(200).json({ status: 'success', data: order })
  }
}
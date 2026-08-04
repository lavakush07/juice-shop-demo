/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

// ---------------------------------------------------------------------------
// IDOR DETECTION TEST — Pattern T1, ORM variant
// Deliberately structured to be as close as possible to the EXISTING,
// correctly-written routes/address.ts -> getAddressById(), which queries:
//   AddressModel.findOne({ where: { id: req.params.id, UserId: req.body.UserId } })
// This version drops only the "UserId: req.body.UserId" clause. The
// hypothesis being tested: a CPG/AI-reasoning engine may be more likely to
// flag a missing-ownership-check when the "correct" version of the exact
// same query shape already exists elsewhere in the same codebase for it
// to compare against, versus the MongoDB/MarsDB-based routes/orderById.ts,
// which has no equally-close correctly-written sibling using the same
// query API.
// ---------------------------------------------------------------------------
export function getAddressByIdInsecure () {
  return async (req: Request, res: Response) => {
    // VULNERABLE: omits "UserId: req.body.UserId" that the real getAddressById()
    // in routes/address.ts includes - any authenticated user can fetch any
    // other user's saved address by ID.
    const address = await AddressModel.findOne({ where: { id: req.params.id } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

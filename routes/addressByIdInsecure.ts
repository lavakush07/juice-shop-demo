/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { AddressModel } from '../models/address'

// Returns a saved address by its ID from the URL path.
export function getAddressByIdInsecure () {
  return async (req: Request, res: Response) => {
    const address = await AddressModel.findOne({ where: { id: req.params.id } })
    if (address != null) {
      res.status(200).json({ status: 'success', data: address })
    } else {
      res.status(400).json({ status: 'error', data: 'Malicious activity detected.' })
    }
  }
}

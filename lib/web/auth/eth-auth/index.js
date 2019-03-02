'use strict'

const Router = require('express').Router
const passport = require('passport')
const EthAuth = require('node-eth-auth')

const config = require('../../../config')
const models = require('../../../models')
const logger = require('../../../logger')
const {
  setReturnToFromReferer
} = require('../utils')

let ethAuth = module.exports = Router()

class EthAuthStreategy extends passport.Strategy {
  constructor (options, verify) {
    if (typeof options === 'function') {
      verify = options
      options = undefined
    }

    options = options || {}

    super(options)

    this.name = options.name || 'eth-auth'
    this._verify = verify
    this._passReqToCallback = options.passReqToCallback || false
  }

  authenticate (req) {
    const verified = (error, user, info) => {
      if (error) {
        return this.error(error)
      }

      if (!user) {
        return this.fail(info)
      }

      this.success(user, info)
    }

    try {
      if (this._passReqToCallback && req) {
        this._verify(req, verified)
      } else {
        this._verify(verified)
      }
    } catch (e) {
      return this.error(e)
    }
  }
}

passport.use(new EthAuthStreategy({
  passReqToCallback: true
}, function (req, done) {
  const address = req.ethAuth.recoveredAddress
  if (!address) {
    return done(new Error('EthAuth failed'), null)
  }

  // construct profile
  const profile = {
    provider: 'ethAuth',
    id: `ethAuth-${address}`,
    emails: []
  }

  const stringifiedProfile = JSON.stringify(profile)
  models.User.findOrCreate({
    where: {
      profileid: address
    },
    defaults: {
      profile: stringifiedProfile
    }
  }).spread(function (user, created) {
    if (user) {
      var needSave = false
      if (user.profile !== stringifiedProfile) {
        user.profile = stringifiedProfile
        needSave = true
      }
      if (needSave) {
        user.save().then(function () {
          if (config.debug) { logger.debug('user login: ' + user.id) }
          return done(null, user)
        })
      } else {
        if (config.debug) { logger.debug('user login: ' + user.id) }
        return done(null, user)
      }
    }
  }).catch(function (err) {
    logger.error('eth auth failed: ' + err)
    return done(err, null)
  })
}))

// TODO: read this from config
const { signature, message, address, banner } = config.ethAuth
let ethAuthMiddleware = new EthAuth({ signature, message, address, banner })

ethAuth.get('/auth/ethAuth/:Address', ethAuthMiddleware, function (req, res) {
  return req.ethAuth.message ? res.send(req.ethAuth.message) : res.status(400).send()
})

ethAuth.post('/auth/ethAuth/:Message/:Signature', ethAuthMiddleware, function (req, res, next) {
  setReturnToFromReferer(req)
  passport.authenticate('eth-auth', {
    successReturnToOrRedirect: true
  })(req, res, next)
})

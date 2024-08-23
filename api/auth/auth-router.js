const router = require('express').Router()
const Users = require('../users/users-model')
const bcrypt = require('bcryptjs')

const {
    checkUsernameFree,
    checkUsernameExists,
    checkPasswordLength
} = require('./auth-middleware')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register', checkUsernameFree, checkPasswordLength, (req, res, next) => {
    let { username, password } = req.body
    password = bcrypt.hashSync(password)
    Users.add({ username, password })
        .then(newUser => {
            res.status(200).json(newUser)
        })
        .catch(next)
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, (req, res) => {
    const { username, password } = req.body
    const { password: correctPW } = req.user
    if (username && bcrypt.compareSync(String(password), correctPW)) {
        req.session.name = 'chocolatechip'
        res.status(200).json({ message: `Welcome ${username}!` })
    } else {
        res.status(401).json({ message: "Invalid credentials" })
    }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', (req, res, next) => {
    if (req.session && req.session.name === 'chocolatechip') {
        req.session.destroy(err => {
            if (err) {
                next(err)
            } else {
                res.status(200).json({ message: "logged out" })
            }
        })
    } else {
        res.status(200).json({ message: "no session" })
    }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router
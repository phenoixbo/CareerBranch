const express = require('express');
const router = express.Router();
const {
  register,
  login,
  googleSignIn,
  sendOtp,
  resetPassword
} = require('../controllers/authController.js');

router.post('/register', register);
router.post('/login', login);
router.post('/google-signin', googleSignIn);
router.post('/forgot-password', sendOtp);
router.post('/reset-password', resetPassword);

module.exports = router;

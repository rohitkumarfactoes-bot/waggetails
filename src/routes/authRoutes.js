const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authProtect } = require('../middleware/authMiddleware');
const passport = require('passport');

//  REGULAR SIGNUP FLOW 
router.post('/signup/initiate', authController.signupInitiate);
router.post('/signup/verify-otp', authController.verifyOtp);
router.post('/signup/resend-otp', authController.resendOtp);
router.post('/signup/dob', authController.saveDob);
router.post('/signup/accept-terms', authController.acceptTerms);

//  LOGIN & LOGOUT 
router.post('/login', authController.login);
router.post('/logout', authProtect(), authController.logout);

//  SOCIAL AUTH 
// Google
router.get('/google', passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false
}));
router.get('/google/callback', (req, res, next) => {
    passport.authenticate('google', { session: false }, async (err, profile) => {
        if (err) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=google_auth_failed`);
        }
        if (!profile) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_profile`);
        }
        return await authController.handleSocialAuth(profile, 'google', res);
    })(req, res, next);
});

// Instagram
router.get('/instagram', passport.authenticate('instagram', { session: false }));
router.get('/instagram/callback', (req, res, next) => {
    passport.authenticate('instagram', { session: false }, async (err, profile) => {
        if (err) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=instagram_auth_failed`);
        }
        if (!profile) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_profile`);
        }
        return await authController.handleSocialAuth(profile, 'instagram', res);
    })(req, res, next);
});

// TikTok
router.get('/tiktok', passport.authenticate('tiktok', {
    scope: ['user.info.basic'],
    session: false
}));
router.get('/tiktok/callback', (req, res, next) => {
    passport.authenticate('tiktok', { session: false }, async (err, profile) => {
        if (err) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=tiktok_auth_failed`);
        }
        if (!profile) {
            return res.redirect(`${process.env.FRONTEND_URL}/login?error=no_profile`);
        }
        return await authController.handleSocialAuth(profile, 'tiktok', res);
    })(req, res, next);
});

module.exports = router;
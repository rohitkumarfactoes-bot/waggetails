const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const TikTokStrategy = require("passport-tiktok-auth").Strategy;

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "https://waggetails.onrender.com/api/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        return done(null, profile);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

// Instagram now uses Facebook/Meta Graph API
passport.use(
  "instagram",
  new FacebookStrategy(
    {
      clientID: process.env.INSTAGRAM_CLIENT_ID,
      clientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
      callbackURL: "https://waggetails.onrender.com/api/v1/auth/instagram/callback",
      authorizationURL: "https://www.facebook.com/v18.0/dialog/oauth",
      tokenURL: "https://graph.facebook.com/v18.0/oauth/access_token",
      graphAPIVersion: "v18.0",
      profileURL: "https://graph.instagram.com/me",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        return done(null, profile);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.use(
  new TikTokStrategy(
    {
      clientID: process.env.TIKTOK_CLIENT_ID,
      clientSecret: process.env.TIKTOK_CLIENT_SECRET,
      callbackURL: "https://waggetails.onrender.com/api/v1/auth/tiktok/callback",
      scope: ["user.info.basic", "user.info.profile"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        return done(null, profile);
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

module.exports = passport;
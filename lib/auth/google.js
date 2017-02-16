const _ = require('lodash');
const async = require('async');
const keystone = require('keystone');
const passport = require('passport');
const passportGoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const User = keystone.list('User');
const applicationLogger = require('timestamp-logger');

const credentials = {
	clientID: process.env.GOOGLE_CLIENT_ID,
	clientSecret: process.env.GOOGLE_CLIENT_SECRET,
	callbackURL: process.env.GOOGLE_CALLBACK_URL,

	scope: 'profile email'
};

exports.authenticateUser = function (req, res, next) {
	const redirect = '/auth/confirm';

	// Begin process
	applicationLogger('[services.google] - Triggered authentication process...');

	// Initialise Google credentials
	const googleStrategy = new passportGoogleStrategy(credentials, function (accessToken, refreshToken, profile, done) {
		done(null, {
			accessToken: accessToken,
			refreshToken: refreshToken,
			profile: profile
		});
	});

	// Pass through authentication to passport
	passport.use(googleStrategy);

	// Save user data once returning from Google
	if (_.has(req.query, 'cb')) {

		applicationLogger('[services.google] - Callback workflow detected, attempting to process data...');

		passport.authenticate('google', {session: false}, function (err, data) {

			if (err || !data) {
				applicationLogger(`[services.google] - Error retrieving Google account data - ${JSON.stringify(err)}`);
				return res.redirect('/sign-in');
			}

			applicationLogger('[services.google] - Successfully retrieved Google account data, processing...');

			req.session.auth = {
				type: 'google',

				name: {
					first: data.profile.name.givenName,
					last: data.profile.name.familyName
				},

				email: data.profile.emails.length ? _.first(data.profile.emails).value : null,

				website: data.profile._json.blog,

				profileId: data.profile.id,

				username: data.profile.username,
				avatar: data.profile._json.picture,

				accessToken: data.accessToken,
				refreshToken: data.refreshToken
			};

			return res.redirect(redirect);

		})(req, res, next);

		// Perform initial authentication request to Google
	} else {

		applicationLogger('[services.google] - Authentication workflow detected, attempting to request access...');

		passport.authenticate('google', {accessType: 'offline'})(req, res, next); // approvalPrompt: 'force'

	}

};

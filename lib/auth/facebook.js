const _ = require('lodash');
const async = require('async');
const keystone = require('keystone');
const passport = require('passport');
const passportFacebookStrategy = require('passport-facebook').Strategy;
const User = keystone.list('User');
const applicationLogger = require('timestamp-logger');

const credentials = {
	clientID: process.env.FACEBOOK_CLIENT_ID,
	clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
	callbackURL: process.env.FACEBOOK_CALLBACK_URL
};

if (process.env.FACEBOOK_API >= 2.4) {
	credentials.profileFields = ['id', 'birthday', 'email', 'first_name', 'gender', 'last_name', 'displayName'];
}

exports.authenticateUser = function (req, res, next) {
	const redirect = '/auth/confirm';

	// Begin process
	applicationLogger('[services.facebook] - Triggered authentication process...');

	// Initialise Facebook credentials
	const facebookStrategy = new passportFacebookStrategy(credentials, function (accessToken, refreshToken, profile, done) {
		done(null, {
			accessToken: accessToken,
			refreshToken: refreshToken,
			profile: profile
		});
	});

	// Pass through authentication to passport
	passport.use(facebookStrategy);

	// Save user data once returning from Facebook
	if (_.has(req.query, 'cb')) {

		applicationLogger('[services.facebook] - Callback workflow detected, attempting to process data...');

		passport.authenticate('facebook', {session: false}, function (err, data) {

			if (err || !data) {
				applicationLogger(`[services.facebook] - Error retrieving Facebook account data - ${JSON.stringify(err)}`);
				return res.redirect('/sign-in');
			}

			applicationLogger('[services.facebook] - Successfully retrieved Facebook account data, processing...');

			const name = data.profile && data.profile.displayName ? data.profile.displayName.split(' ') : [];

			req.session.auth = {
				type: 'facebook',

				name: {
					first: name.length ? name[0] : '',
					last: name.length > 1 ? name[1] : ''
				},

				email: data.profile.emails.length ? _.first(data.profile.emails).value : null,

				website: data.profile._json.blog,

				profileId: data.profile.id,

				username: data.profile.username,
				avatar: `https://graph.facebook.com/${data.profile.id}/picture?width=600&height=600`,

				accessToken: data.accessToken,
				refreshToken: data.refreshToken
			};

			return res.redirect(redirect);

		})(req, res, next);

		// Perform initial authentication request to Facebook
	} else {

		applicationLogger('[services.facebook] - Authentication workflow detected, attempting to request access...');

		passport.authenticate('facebook', {scope: ['email']})(req, res, next);

	}

};

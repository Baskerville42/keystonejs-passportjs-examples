const _ = require('lodash');
const async = require('async');
const keystone = require('keystone');
const passport = require('passport');
const passportTwitterStrategy = require('passport-twitter').Strategy;
const User = keystone.list('User');
const applicationLogger = require('timestamp-logger');

const credentials = {
	consumerKey: process.env.TWITTER_CONSUMER_KEY,
	consumerSecret: process.env.TWITTER_CONSUMER_SECRET,
	callbackURL: process.env.TWITTER_CALLBACK_URL
};

exports.authenticateUser = function (req, res, next) {
	const redirect = '/auth/confirm';

	// Begin process
	applicationLogger('[services.twitter] - Triggered authentication process...');

	// Initialise Twitter credentials
	const twitterStrategy = new passportTwitterStrategy(credentials, function (accessToken, refreshToken, profile, done) {
		done(null, {
			accessToken: accessToken,
			refreshToken: refreshToken,
			profile: profile
		});
	});

	// Pass through authentication to passport
	passport.use(twitterStrategy);

	// Save user data once returning from Twitter
	if (_.has(req.query, 'cb')) {

		applicationLogger('[services.twitter] - Callback workflow detected, attempting to process data...');

		passport.authenticate('twitter', {session: false}, function (err, data) {

			if (err || !data) {
				applicationLogger(`[services.twitter] - Error retrieving Twitter account data - ${JSON.stringify(err)}`);
				return res.redirect('/sign-in');
			}

			applicationLogger('[services.twitter] - Successfully retrieved Twitter account data, processing...');

			const name = data.profile && data.profile.displayName ? data.profile.displayName.split(' ') : [];
			const profileJSON = JSON.parse(data.profile._raw);
			const urls = profileJSON.entities.url && profileJSON.entities.url.urls && profileJSON.entities.url.urls.length ? profileJSON.entities.url.urls : [];

			req.session.auth = {
				type: 'twitter',

				name: {
					first: name.length ? name[0] : '',
					last: name.length > 1 ? name[1] : ''
				},

				website: urls.length ? urls[0].expanded_url : '',

				profileId: data.profile.id,

				username: data.profile.username,
				avatar: data.profile._json.profile_image_url.replace('_normal', ''),

				accessToken: data.accessToken,
				refreshToken: data.refreshToken
			};

			return res.redirect(redirect);

		})(req, res, next);

		// Perform initial authentication request to Twitter
	} else {

		applicationLogger('[services.twitter] - Authentication workflow detected, attempting to request access...');

		passport.authenticate('twitter')(req, res, next);

	}

};

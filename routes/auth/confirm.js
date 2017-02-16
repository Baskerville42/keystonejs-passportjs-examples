const keystone = require('keystone');
const async = require('async');
const request = require('request');
const _ = require('lodash');
const User = keystone.list('User');
const applicationLogger = require('timestamp-logger');

exports = module.exports = function (req, res) {

	const view = new keystone.View(req, res);
	let locals = res.locals;

	locals.section = 'profile';
	locals.form = req.body;
	locals.returnto = req.query.returnto;

	locals.authUser = req.session.auth;
	locals.existingUser = false;

	// Reject request if no auth data is stored in session
	if (!locals.authUser) {
		applicationLogger('[auth.confirm] - No auth data detected, redirecting to sign in.');
		return res.redirect('/sign-in');
	}

	// Set existing user if already logged in
	if (req.user) {
		locals.existingUser = req.user;
	}

	// Function to handle sign in
	const doSignIn = function () {

		applicationLogger('[auth.confirm] - Signing in user...');

		const onSuccess = function () {
			applicationLogger('[auth.confirm] - Successfully signed in.');
			return res.redirect(req.cookies.target || '/me');
		};

		const onFail = function (err) {
			applicationLogger(`[auth.confirm] - Failed signing in. ${err}`);
			req.flash('error', {detail: 'Sorry, there was an issue signing you in, please try again.'});
			return res.redirect('/sign-in');
		};

		keystone.session.signin(String(locals.existingUser._id), req, res, onSuccess, onFail);

	};

	// Function to check if a user already exists for this profile id (and sign them in)
	const checkExisting = function (next) {

		if (locals.existingUser) return checkAuth();

		applicationLogger(`[auth.confirm] - Searching for existing users via [${locals.authUser.type}] profile id...`);

		const query = User.model.findOne();
		query.where('services.' + locals.authUser.type + '.profileId', locals.authUser.profileId);
		query.exec(function (err, user) {
			if (err) {
				applicationLogger(`[auth.confirm] - Error finding existing user via profile id. ${err}`);
				return next({message: 'Sorry, there was an error processing your information, please try again.'});
			}
			if (user) {
				applicationLogger(`[auth.confirm] - Found existing user via [${locals.authUser.type}] profile id...`);
				locals.existingUser = user;
				return doSignIn();
			}
			return next();
		});

	};

	// Function to handle data confirmation process
	const checkAuth = function () {

		async.series([

			// Check for user by email (only if not signed in)
			function (next) {

				if (locals.existingUser) return next();

				applicationLogger(`[auth.confirm] - Searching for existing users via [${locals.authUser.email}] email address...`);

				const query = User.model.findOne();
				query.where('email', locals.form.email);
				query.exec(function (err, user) {
					if (err) {
						applicationLogger(`[auth.confirm] - Error finding existing user via email. ${err}`);
						return next({message: 'Sorry, there was an error processing your information, please try again.'});
					}
					if (user) {
						applicationLogger('[auth.confirm] - Found existing user via email address...');
						return next({message: 'There\'s already an account with that email address, please sign-in instead.'});
					}
					return next();
				});

			},

			// Create or update user
			function (next) {

				if (locals.existingUser) {
					
					applicationLogger('[auth.confirm] - Existing user found, updating...');

					const userData = {
						state: 'enabled',

						website: locals.form.website,

						isVerified: true,

						services: locals.existingUser.services || {}
					};

					_.extend(userData.services[locals.authUser.type], {
						isConfigured: true,

						profileId: locals.authUser.profileId,

						username: locals.authUser.username,
						avatar: locals.authUser.avatar,

						accessToken: locals.authUser.accessToken,
						refreshToken: locals.authUser.refreshToken
					});

					// applicationLogger(`[auth.confirm] - Existing user data: ${userData}`);

					locals.existingUser.set(userData);

					locals.existingUser.save(function (err) {
						if (err) {
							applicationLogger(`[auth.confirm] - Error saving existing user. ${err}`);
							return next({message: 'Sorry, there was an error processing your account, please try again.'});
						}
						applicationLogger('[auth.confirm] - Saved existing user.');
						return next();
					});

				} else {

					applicationLogger('[auth.confirm] - Creating new user...');

					const userData = {
						name: {
							first: locals.form['name.first'],
							last: locals.form['name.last']
						},
						email: locals.form.email,
						password: Math.random().toString(36).slice(-8),

						state: 'enabled',

						website: locals.form.website,

						isVerified: true,

						services: {}
					};

					userData.services[locals.authUser.type] = {
						isConfigured: true,

						profileId: locals.authUser.profileId,

						username: locals.authUser.username,
						avatar: locals.authUser.avatar,

						accessToken: locals.authUser.accessToken,
						refreshToken: locals.authUser.refreshToken
					};

					applicationLogger(`[auth.confirm] - New user data: ${userData}`);

					locals.existingUser = new User.model(userData);

					locals.existingUser.save(function (err) {
						if (err) {
							applicationLogger(`[auth.confirm] - Error saving new user. ${err}`);
							return next({message: 'Sorry, there was an error processing your account, please try again.'});
						}
						applicationLogger('[auth.confirm] - Saved new user.');
						return next();
					});

				}

			},

			// Session
			function () {
				if (req.user) {
					applicationLogger('[auth.confirm] - Already signed in, skipping sign in.');
					return res.redirect(req.cookies.target || '/me');
				}
				return doSignIn();
			}

		], function (err) {
			if (err) {
				applicationLogger(`[auth.confirm] - Issue signing user in. ${err}`);
				req.flash('error', {detail: err.message || 'Sorry, there was an issue signing you in, please try again.'});
				return res.redirect('/sign-in');
			}
		});

	};

	view.on('init', function (next) {
		return checkExisting(next);
	});

	view.on('post', {action: 'confirm.details'}, function (next) {
		if (!locals.form['name.first'] || !locals.form['name.last'] || !locals.form.email) {
			req.flash('error', {detail:'Please enter a name & email.'});
			return next();
		}
		return checkAuth();
	});

	view.render('auth/confirm', {layout: 'auth'});

};

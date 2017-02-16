const keystone = require('keystone');
const applicationLogger = require('timestamp-logger');

exports = module.exports = function (req, res) {

	if (req.user) {
		return res.redirect(req.cookies.target || '/me');
	}

	const view = new keystone.View(req, res);
	let locals = res.locals;

	locals.section = 'session';
	locals.form = req.body;

	view.on('post', {action: 'sign-in'}, function (next) {

		// Begin process
		applicationLogger('[sign-in] - Triggered authentication process...');

		if (!req.body.email || !req.body.password) {
			req.flash('error', {detail: 'Please enter your username and password.'});
			return next();
		}

		const onSuccess = function () {
			if (req.body.target && !/join|signin/.test(req.body.target)) {
				applicationLogger(`[sign-in] - Set target as [${req.body.target}].`);
				res.redirect(req.body.target);
			} else {
				res.redirect('/me');
			}
		};

		const onFail = function () {
			req.flash('error', {detail: 'Your username or password were incorrect, please try again.'});
			return next();
		};

		keystone.session.signin({email: req.body.email, password: req.body.password}, req, res, onSuccess, onFail);

	});

	view.render('session/sign-in', {layout: 'auth'});

};

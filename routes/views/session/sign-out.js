const keystone = require('keystone');

exports = module.exports = function (req, res) {

	let locals = res.locals;

	locals.section = 'session';

	keystone.session.signout(req, res, function () {
		res.redirect('/');
	});

};

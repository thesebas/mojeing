var request = require('request-promise');
var crypto = require('crypto');
var Promise = require('bluebird');

function mixShortPasswdMask (mask, salt, passwd) {
	passwd = passwd.split('');
	salt = salt.split('');
	return mask.split('').map(function (i, k) {
		return i === '+' ? salt[k]: passwd.shift();
	}).join('');
}

function mixFullPasswdMask (mask, salt, passwd) {
	passwd = passwd.split('');
	salt = salt.split('');
	return mask.split('').map(function (i, k) {
		return i === '+' ? salt[k]: passwd[k];
	}).join('');
}

function hashPassword (key, passwordmix) {
	var hmac = crypto.createHmac('sha1', key);
	hmac.setEncoding('hex');
	hmac.write(passwordmix);
	hmac.end();
	return hmac.read();
}

function getApi (options) {
	options = options || {};
	var token = '';
	var locale = options.locale || 'PL';

	function callApi (method, data, trace) {
		var body = {locale: locale,  token: token, trace: trace || ''};

		if (data) {
			body.data = data;
		}

		return request({
			url: 'https://login.ingbank.pl/mojeing/rest/' + method,
			method: 'POST',
			json: true,
			jar: true,
			headers: {
				'Content-type': 'application/json',
				'X-Wolf-Protection': Math.random()
			},
			forever: true,
			body: body
		}).then(function (resp) {
			if (resp.status != 'OK') {
				throw new Error('METHOD ERROR :' + method, resp)
			}
			if (resp.data && resp.data.token) {
				token = resp.data.token;
			}
			return resp.data;
		}, function (err) {
			console.error('REQUEST ERROR');
			throw err;
		});
	}

	function checklogin (login) {
		return callApi('renchecklogin', {login: login});
	}

	function login (prelogindata, login, passwd) {
		var mixedpasswd = mixFullPasswdMask(prelogindata.mask, prelogindata.salt, passwd);
		var pwdhash = hashPassword(prelogindata.key, mixedpasswd);
		return callApi('renlogin', {pwdhash: pwdhash, login: login});
	}

	function authorize (username, password) {
		return checklogin(username)
			.then(function (resp) {
				return login(resp, username, password);
			});
	}

	return {
		callApi,
		// checklogin,
		// login,
		authorize,
		getToken() {return token;}
	};
}

module.exports = getApi;

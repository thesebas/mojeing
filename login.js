var request = require('request-promise');
var crypto = require('crypto');
var Promise = require('bluebird');

var {username , password} = require('./stuff/passwd');
var token = '';

function callApi (method, data, trace) {
	var body = {locale: 'PL',  token: token, trace: trace || ''};

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
		},
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
		console.error(err);
	});
}

function checklogin (login) {
	return callApi('renchecklogin', {login: login});
}

function login (login, passwd) {
	return function (prelogindata) {
		var mixedpasswd = mixFullPasswdMask(prelogindata.mask, prelogindata.salt, passwd);
		var pwdhash = hashPassword(prelogindata.key, mixedpasswd);
		return callApi('renlogin', {pwdhash: pwdhash, login: login});
	};
}

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

checklogin(username)
	.then(login(username, password))
	.then(function () {
		return callApi('rengetproperties', {prefix: 'CONFIG'})
			.then(function (resp) {
				console.log(resp);
			}, function (err) {
				console.error(err);
			});
	}).catch(function (err) {
	console.error(err);
});

// methods with (token, locale)
// rengetmainpageprds ()
// rengetnotification ({scmode: "D"})
// rengetallaccounts ()
// rengetinv ()
// rengetallcards ()
// rengetproperties ({prefix: "LIQUID"|"CONFIG"|"LOGIN"|"ADVERT"})
// rengetfury ({fromDate: "2015-07-13", toDate: "2016-01-13", rach: [], search: "", maxTrn: 34, skipTrn: 0, maxsug: 0})

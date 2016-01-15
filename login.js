var {username , password} = require('./stuff/passwd');

var mojeing = require('./lib/mojeing')();

function dumpJson (data) {
	console.log(JSON.stringify(data, null, ' '));
}

mojeing.authorize(username , password)
	.then(function () {
		return mojeing.callApi('rengetallaccounts');
	})
	.then(function (resp) {
		dumpJson(resp);
		console.log(mojeing.getToken());
	});

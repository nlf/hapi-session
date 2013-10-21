var Hapi = require('hapi');
var session = require('../');
var server = new Hapi.Server('127.0.0.1', 8000);

var config = {
    password: 'testing',
    isSecure: false,
    redirectTo: '/login'
};

server.auth('session', {
    implementation: new session(server, config),
    defaultMode: true
});

server.route({
    method: 'get',
    path: '/login',
    config: {
        auth: {
            mode: 'try'
        }
    },
    handler: function (request) {
        request.auth.session.set({ user: 'nathan' });
        request.reply.redirect('/');
    }
});

server.route({
    method: 'get',
    path: '/',
    handler: function (request) {
        var msg = 'sup, ' + request.auth.credentials.user;
        request.reply(msg);
    }
});

server.start(function () {
    console.log('server running at:', server.info.uri);
});


var Hoek = require('hoek');
var rack = require('hat').rack();

var Scheme = function (server, options) {

    Hoek.assert(this.constructor === Scheme, 'Scheme must be instantiated using new');
    Hoek.assert(server, 'Server is required');
    Hoek.assert(options, 'Invalid options');
    Hoek.assert(!options.validateFunc || typeof options.validateFunc === 'function', 'Invalid validateFunc method in options');
    Hoek.assert(options.password, 'Missing required password in options');
    Hoek.assert(!options.appendNext || options.redirectTo, 'Cannot set appendNext without redirectTo');

    this.hapi = server.pack.hapi;
    this.settings = Hoek.clone(options);
    this.settings.ttl = this.settings.ttl || 1000 * 60 * 24;
    this.settings.cookie = this.settings.cookie || 'sid';

    var cookieOptions = {
        encoding: 'iron',
        password: this.settings.password,
        isSecure: this.settings.isSecure !== false,
        isHttpOnly: this.settings.isHttpOnly !== false,
        path: '/'
    };

    if (this.settings.ttl) {
        cookieOptions.ttl = this.settings.ttl;
    }

    server.state(this.settings.cookie, cookieOptions);

    if (typeof this.settings.appendNext === 'boolean') {
        this.settings.appendNext = this.settings.appendNext ? 'next' : '';
    }

    return this;
};

Scheme.prototype.authenticate = function (request, callback) {
    var self = this;

    callback = Hoek.nextTick(callback);

    var validate = function () {
        var sessionId;

        if (!request.state.hasOwnProperty(self.settings.cookie)) {
            return unauthenticated(self.hapi.error.unauthorized());
        }

        sessionId = request.state[self.settings.cookie];
        request.server.pack._cache.get({ segment: '_sessions', id: sessionId }, function (err, session) {
            if (!session) {
                return unauthenticated(self.hapi.error.unauthorized());
            }

            // we have the session
            if (!self.settings.validateFunc) {
                return callback(null, session.item);
            }

            self.settings.validateFunc(session.item, function (err, isValid, credentials) {
                if (err || !isValid) {
                    if (self.settings.clearInvalid) {
                        request.clearState(self.settings.cookie);
                        request.server.pack._cache.drop({ segment: '_sessions', id: sessionId }, function (err) {
                            return unauthenticated(self.hapi.error.unauthorized('Invalid cookie'), session.item, { log: (err ? { data: err } : 'Failed validation') });
                        });
                    }
                }

                if (credentials) {
                    request.server.pack._cache.set({ segment: '_sessions', id: sessionId }, credentials, self.settings.ttl, function (err) {
                        return callback(err, credentials);
                    });
                }

                return callback(null, session.item);
            });
        });
    };

    var unauthenticated = function (err, session, options) {
        if (!self.settings.redirectTo) {
            return callback(err, session, options);
        }

        var uri = self.settings.redirectTo;
        if (self.settings.appendNext) {
            if (uri.indexOf('?') !== -1) {
                uri += '&';
            } else {
                uri += '?';
            }
            
            uri += self.settings.appendNext + '=' + encodeURIComponent(request.url.path);
        }

        return callback(new self.hapi.response.Redirection(uri), session, options);
    };

    validate();
};

Scheme.prototype.extend = function (request) {
    var self = this;

    Hoek.assert(!request.auth.session, 'The session scheme may not be registered more than once, nor with the cookie scheme');

    request.auth.session = {
        set: function (session, callback) {
            Hoek.assert(session && typeof session === 'object', 'Invalid session');

            var sessionId;

            if (request.state.hasOwnProperty(self.settings.cookie)) {
                sessionId = request.state[self.settings.cookie];
                // we have a session id already, so just fetch it and reuse it
            } else {
                sessionId = rack();
                request.setState(self.settings.cookie, sessionId);
                // make a new session id and save the cookie
            }

            request.server.pack._cache.set({ segment: '_sessions', id: sessionId }, session, self.settings.ttl, function (err) {
                // save to the configured server cache
                if (typeof callback === 'function') callback(err);
            });
        },
        clear: function (callback) {
            var session;

            if (request.state.hasOwnProperty(self.settings.cookie)) {
                session = request.state[self.settings.cookie];

                request.server.pack._cache.drop({ segment: '_sessions', id: session }, function (err) {
                    // remove the session from the cache
                    if (typeof callback === 'function') callback(err);
                });
            }

            request.clearState(self.settings.cookie);
            // delete the cookie
        }
    };
};

module.exports = Scheme;

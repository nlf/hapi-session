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
    this.settings.ttl = this.settings.ttl || 1000 * 60 * 60 * 24; // one day
    this.settings.cookie = this.settings.cookie || 'sid';
    this.cache = server.cache('_sessions', { expiresIn: this.settings.ttl });

    var cookieOptions = {
        encoding: 'iron',
        ttl: this.settings.ttl,
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
        if (typeof sessionId !== 'string') {
            return unauthenticated(self.hapi.error.unauthorized());
        }

        self.cache.get(sessionId, function (err, session) {
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
                        self.cache.drop(sessionId, function (err) {
                            return unauthenticated(self.hapi.error.unauthorized('Invalid cookie'), session.item, { log: (err ? { data: err } : 'Failed validation') });
                        });
                    }
                }

                if (credentials) {
                    self.cache.set(sessionId, credentials, 0, function (err) {
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
                if (typeof sessionId !== 'string') {
                    // we have an invalid cookie set, so overwrite it
                    sessionId = rack();
                    request.setState(self.settings.cookie, sessionId);
                }
                // we have a session id already, so just fetch it and reuse it
            } else {
                sessionId = rack();
                request.setState(self.settings.cookie, sessionId);
                // make a new session id and save the cookie
            }

            self.cache.set(sessionId, session, 0, function (err) {
                // save to the configured server cache
                if (typeof callback === 'function') callback(err);
            });
            
            // return the sessionId for some use cases
            return sessionId;
        },
        clear: function (callback) {
            var sessionId;

            if (request.state.hasOwnProperty(self.settings.cookie)) {
                sessionId = request.state[self.settings.cookie];

                self.cache.drop(sessionId, function (err) {
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

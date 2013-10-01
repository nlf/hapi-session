Hapi-Session
------------

This is a session based auth scheme for Hapi. A lot of the code was gratuitously stolen from the cookie auth scheme in the Hapi code, and this module works in much the same way. The biggest difference is in that rather than storing the entire session object in the cookie, this module stores only an ID. The rest of the data is stored in your Hapi server's cache, and retrieved when required. This gets around the issue of storing large amounts of data in the session without causing a race condition.

For example usage see the server.js in the examples directory

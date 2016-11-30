'use strict';

var _ = require('lodash');
var Boom = require('boom');
var samlHapi = require('./saml-hapi');

/**
 * Method to register the plugin with hapi
 * @param {object} server The server object
 * @param {object} options Additional options object
 * @param {function} next Callback function once plugin is registered
 */
var registerPlugin = function (server, options, next) {

  server.auth.scheme('saml', function (requestServer, requestOptions) {
    var settings = _.clone(requestOptions);
    return {
      authenticate: samlHapi.authenticate(settings)
    };
  });

  server.auth.strategy('saml-strategy', 'saml', options);

  var settings = _.clone(options);

  var loginPath = settings.loginPath || '/login';
  var loginComplete = settings.loginComplete || '/loginComplete';
  var pathLogout = settings.pathLogout ||'/logout';
  var redirectTo = settings.redirectTo || '/';
  // Instead of always redirecting, allow developers to specify
  // the exact handler action they want to perform if samlSetAccount
  // is successful.
  var delegateLoginComplete = settings.onLoginComplete ||
    function(request, reply, profile, redirectUrl) {
      if (redirectUrl) {
        return reply.redirect(redirectUrl);
      };
      return reply.redirect(redirectTo);
  };

  /**
   * This route is not called, but rather it's used to redirect the user
   * to the SAML server
   */
  server.route({
    path: loginPath,
    method: 'GET',
    config: {
      auth: 'saml-strategy',
      handler: function (request, reply) {
        // do nothing here
      }
    }
  });

  /**
   *  This route is where the SAML token is posted back to
   */
  server.route({
    path: loginComplete,
    method: 'POST',
    config: {
      auth: false,
      handler: function (request, reply) {

        /**
         * Function to call the verification of the token
         * @param profile
         * @param done
         */
        settings.verifyFunc = function (profile, done) {
          settings.samlSetAccount(request, reply, profile, function (err, profile, redirectUrl) {
            if (err) {
              return reply((err.isBoom) ? err : Boom.badRequest(err));
            }
            return delegateLoginComplete(request, reply, profile, redirectUrl);
          });
        };

        samlHapi.authenticate(settings)(request, reply);
      }
    }
  });

  /**
   * Route to clear the SAML token.
   * TODO: Do a proper SAML logout implementation
   */
  server.route({
    path: pathLogout,
    method: 'GET',
    config: {
      handler: function(request, reply) {

        var options = {
          user: {
            nameID: request.state.data.name,
            nameIDFormat: settings.nameIDFormat || "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            sessionIndex: request.state.data.session
          }
        };

        samlHapi.logout(settings, options, function(err, url) {
          if (err != null) { return reply.code(500); }

          request.auth.session.clear();
          reply.redirect(url);
        });
      }
    }
  });

  next();
};

registerPlugin.attributes = {
  pkg: require('../package.json')
};

module.exports = registerPlugin;

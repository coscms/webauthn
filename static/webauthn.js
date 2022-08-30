(function () {
  function check() {
    // check whether current browser supports WebAuthn
    if (!window.PublicKeyCredential) {
      alert("Error: this browser does not support WebAuthn");
      return false;
    }
    return true
  }

  function isSupported() {
    return typeof(window.PublicKeyCredential)!='undefined';
  }

  // Base64 to ArrayBuffer
  function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
  }

  // ArrayBuffer to URLBase64
  function bufferEncode(value) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  function webAuthn(options) {
    var $this = this;
    this.options = {
      urlPrefix: '/webauthn',
      debug: false,
      getRegisterData: function () { return {} },
      getLoginData: function () { return {} },
      getUnbindData: function () { return {} },
      onRegisterSuccess: function (response) {$this.options.debug && console.log(response)},
      onRegisterError: function (error) {$this.options.debug && console.error(error)},
      onLoginSuccess: function (response) {$this.options.debug && console.log(response)},
      onLoginError: function (error) {$this.options.debug && console.error(error)},
      onUnbindSuccess: function (response) {$this.options.debug && console.log(response)},
      onUnbindError: function (error) {$this.options.debug && console.error(error)},
    }
    $.extend(this.options, options || {});
  }

  webAuthn.prototype.check = check;
  webAuthn.prototype.isSupported = isSupported();
  webAuthn.prototype.register = function (username) {
    if (username === "") {
      alert("Please enter a username");
      return;
    }
    var $this = this;

    $.post(
      $this.options.urlPrefix + '/register/begin/' + username,
      $this.options.getRegisterData(),
      function (data) {
        return data
      },
      'json')
      .then((credentialCreationOptions) => {
        $this.options.debug && console.log(credentialCreationOptions);
        credentialCreationOptions.publicKey.challenge = bufferDecode(credentialCreationOptions.publicKey.challenge);
        credentialCreationOptions.publicKey.user.id = bufferDecode(credentialCreationOptions.publicKey.user.id);
        if (credentialCreationOptions.publicKey.excludeCredentials) {
          for (var i = 0; i < credentialCreationOptions.publicKey.excludeCredentials.length; i++) {
            credentialCreationOptions.publicKey.excludeCredentials[i].id = bufferDecode(credentialCreationOptions.publicKey.excludeCredentials[i].id);
          }
        }

        return navigator.credentials.create({
          publicKey: credentialCreationOptions.publicKey
        })
      })
      .then((credential) => {
        $this.options.debug && console.log(credential);
        let attestationObject = credential.response.attestationObject;
        let clientDataJSON = credential.response.clientDataJSON;
        let rawId = credential.rawId;

        $.post(
          $this.options.urlPrefix + '/register/finish/' + username,
          JSON.stringify({
            id: credential.id,
            rawId: bufferEncode(rawId),
            type: credential.type,
            response: {
              attestationObject: bufferEncode(attestationObject),
              clientDataJSON: bufferEncode(clientDataJSON),
            },
          }),
          function (data) {
            return data
          },
          'json')
      })
      .then((success) => {
        $this.options.debug && alert("successfully registered " + username + "!");
        $this.options.onRegisterSuccess.apply(this, arguments);
      })
      .catch((error) => {
        console.log(error);
        alert("failed to register " + username);
        $this.options.onRegisterError.apply(this, arguments);
      })
  }

  webAuthn.prototype.auth = function (username, type) {
    if (username === "") {
      alert("Please enter a username");
      return;
    }
    var $this = this;

    $.post(
      $this.options.urlPrefix + '/'+type+'/begin/' + username,
      type=='login'?$this.options.getLoginData():$this.options.getUnbindData(),
      function (data) {
        return data
      },
      'json')
      .then((credentialRequestOptions) => {
        $this.options.debug && console.log(credentialRequestOptions);
        credentialRequestOptions.publicKey.challenge = bufferDecode(credentialRequestOptions.publicKey.challenge);
        credentialRequestOptions.publicKey.allowCredentials.forEach(function (listItem) {
          listItem.id = bufferDecode(listItem.id)
        });

        return navigator.credentials.get({
          publicKey: credentialRequestOptions.publicKey
        })
      })
      .then((assertion) => {
        $this.options.debug && console.log(assertion);
        let authData = assertion.response.authenticatorData;
        let clientDataJSON = assertion.response.clientDataJSON;
        let rawId = assertion.rawId;
        let sig = assertion.response.signature;
        let userHandle = assertion.response.userHandle;

        $.post(
          $this.options.urlPrefix + '/'+type+'/finish/' + username,
          JSON.stringify({
            id: assertion.id,
            rawId: bufferEncode(rawId),
            type: assertion.type,
            response: {
              authenticatorData: bufferEncode(authData),
              clientDataJSON: bufferEncode(clientDataJSON),
              signature: bufferEncode(sig),
              userHandle: bufferEncode(userHandle),
            },
          }),
          function (data) {
            return data
          },
          'json')
      })
      .then((success) => {
        $this.options.debug && alert("successfully "+type+" " + username + "!");
        if(type=='login'){
          $this.options.onLoginSuccess.apply(this, arguments);
        }else{
          $this.options.onUnbindSuccess.apply(this, arguments);
        }
      })
      .catch((error) => {
        console.log(error);
        alert("failed to "+type+" " + username);
        if(type=='login'){
          $this.options.onLoginError.apply(this, arguments);
        }else{
          $this.options.onUnbindError.apply(this, arguments);
        }
      })
  }

  webAuthn.prototype.login = function (username) {
    this.auth(username,'login');
  }

  webAuthn.prototype.unbind = function (username) {
    this.auth(username,'unbind');
  }
  window.WebAuthn = webAuthn;
})();
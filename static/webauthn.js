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
    try {
      value = String(value).replace(/_/g,'/').replace(/-/g,'+');
      return Uint8Array.from(atob(value), c => c.charCodeAt(0));
    } catch (error) {
      console.error(error+": "+value);
    }
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
      checkResponseBeginLogin: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
      checkResponseFinishLogin: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
      checkResponseBeginRegister: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
      checkResponseFinishRegister: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
      checkResponseBeginUnbind: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
      checkResponseFinishUnbind: function(data) {
        if(typeof data.Code != 'undefined'){
          App.message({'text':data.Info,'type':data.Code==1?'success':'error'});
          return false;
        }
        return true;
      },
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
        if(!$this.options.checkResponseBeginRegister(data)) return null;
        return data;
      },'json')
      .then((credentialCreationOptions) => {
        $this.options.debug && console.log(credentialCreationOptions);
        if(!credentialCreationOptions || typeof credentialCreationOptions.publicKey == 'undefined'){
          return;
        }
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
        if(!credential || typeof credential.response == 'undefined'){
          return;
        }
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
            if(!$this.options.checkResponseFinishRegister(data)) return null;
            return data;
          }, 'json');
      })
      .then((_) => {
        $this.options.debug && alert("successfully registered " + username + "!");
        $this.options.onRegisterSuccess.apply(this, arguments);
      })
      .catch((error) => {
        console.log("failed to register " + username + ": " + error);
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
        if(type=='login'){
          if(!$this.options.checkResponseBeginLogin(data)) return null;
        }else{
          if(!$this.options.checkResponseBeginUnbind(data)) return null;
        }
        return data;
      },'json')
      .then((credentialRequestOptions) => {
        $this.options.debug && console.log(credentialRequestOptions);
        if(!credentialRequestOptions || typeof credentialRequestOptions.publicKey == 'undefined'){
          return;
        }
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
        if(!assertion || typeof assertion.response == 'undefined'){
          return;
        }
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
            if(type=='login'){
              if(!$this.options.checkResponseFinishLogin(data)) return null;
            }else{
              if(!$this.options.checkResponseFinishUnbind(data)) return null;
            }
            return data;
          }, 'json');
      })
      .then((_) => {
        $this.options.debug && alert("successfully "+type+" " + username + "!");
        if(type=='login'){
          $this.options.onLoginSuccess.apply(this, arguments);
        }else{
          $this.options.onUnbindSuccess.apply(this, arguments);
        }
      })
      .catch((error) => {
        console.log("failed to "+type+" " + username + ": " +error);
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
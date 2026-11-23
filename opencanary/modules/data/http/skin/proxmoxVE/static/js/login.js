/*
 * Proxmox VE login skin behaviour.
 *
 * The real Proxmox VE login window submits the credentials as a form POST to
 * /api2/extjs/access/ticket and then shows an Ext.MessageBox when the login
 * fails.  This skin mirrors that behaviour: with JavaScript enabled the form
 * is submitted in the background (so the URL and the typed user name stay
 * visible) and the "Error" message box is shown; without JavaScript the form
 * falls back to a normal POST and the server-side rendered error state.
 *
 * "Save User name" persists the user name in localStorage, like the ExtJS
 * state provider used by Proxmox VE.
 */
(function () {
  "use strict";

  var STORAGE_SAVE = "login-saveusername";
  var STORAGE_USER = "login-username";
  var LOGIN_URL = "/index.html";
  var ERROR_TEXT = "Login failed:<br>401 Unauthorized<br>Please try again";
  var CONNECTION_ERROR =
    "Connection failure. Network error or Proxmox VE services not running?";

  var form = document.getElementById("login-form");
  if (!form) {
    return;
  }

  var username = document.getElementById("username");
  var password = document.getElementById("password");
  var saveUser = document.getElementById("saveusername");
  var windowMask = document.getElementById("login-mask");
  var errorMessage = document.getElementById("error-message");
  var errorOk = document.getElementById("error-ok");

  function storageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      if (value === null) {
        window.localStorage.removeItem(key);
      } else {
        window.localStorage.setItem(key, value);
      }
    } catch (e) {
      /* storage can be unavailable (private mode); login still works */
    }
  }

  function showWindowMask(show) {
    if (windowMask) {
      windowMask.hidden = !show;
    }
  }

  function showError(html) {
    if (errorMessage && html) {
      errorMessage.innerHTML = html;
    }
    document.body.classList.remove("login-failed");
    document.body.classList.add("is-error");
    if (errorOk) {
      errorOk.focus();
    }
  }

  function hideError() {
    document.body.classList.remove("is-error");
    document.body.classList.remove("login-failed");
    if (password) {
      password.value = "";
    }
    if (username) {
      username.focus();
    }
  }

  /* Restore a previously remembered user name. */
  if (saveUser && storageGet(STORAGE_SAVE) === "1") {
    saveUser.checked = true;
    var savedUser = storageGet(STORAGE_USER);
    if (savedUser !== null && username) {
      username.value = savedUser;
    }
  }

  if (username) {
    if (username.value !== "" && password) {
      password.focus();
    } else {
      username.focus();
    }
  }

  if (errorOk) {
    errorOk.addEventListener("click", hideError);
  }

  /* A plain (non-JavaScript) POST arrived: the server already rendered the
     error state.  Make the message box keyboard friendly. */
  if (document.body.classList.contains("login-failed") && errorOk) {
    errorOk.focus();
  }

  function submitInBackground() {
    if (!window.fetch || !window.URLSearchParams || !window.FormData) {
      return false;
    }

    if (saveUser && saveUser.checked) {
      storageSet(STORAGE_SAVE, "1");
      storageSet(STORAGE_USER, username ? username.value : "");
    } else if (saveUser) {
      storageSet(STORAGE_SAVE, null);
      storageSet(STORAGE_USER, null);
    }

    showWindowMask(true);
    var started = Date.now();
    var body = new URLSearchParams(new FormData(form));

    window
      .fetch(LOGIN_URL, {
        method: "POST",
        body: body,
        credentials: "same-origin",
        keepalive: true,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
      })
      .then(
        function () {
          finish(ERROR_TEXT);
        },
        function () {
          finish(CONNECTION_ERROR);
        }
      );

    function finish(message) {
      /* Keep the "Please wait..." mask up for a moment, like the real GUI
         does while the ticket request is in flight. */
      var elapsed = Date.now() - started;
      var delay = Math.max(0, 400 - elapsed);
      window.setTimeout(function () {
        showWindowMask(false);
        if (password) {
          password.value = "";
        }
        showError(message);
      }, delay);
    }

    return true;
  }

  form.addEventListener("submit", function (event) {
    if (submitInBackground()) {
      event.preventDefault();
    }
  });
})();

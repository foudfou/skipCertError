mitm_me.onFirefoxLoad = function(event) {
  document.getElementById("contentAreaContextMenu")
          .addEventListener("popupshowing", function (e){ mitm_me.showFirefoxContextMenu(e); }, false);
};

mitm_me.showFirefoxContextMenu = function(event) {
  // show or hide the menuitem based on what the context menu is on
  document.getElementById("context-mitm_me").hidden = gContextMenu.onImage;
};

window.addEventListener("load", function () { mitm_me.onFirefoxLoad(); }, false);


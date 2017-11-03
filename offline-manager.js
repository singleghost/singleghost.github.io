function updateFound(){
  var installingWorker = this.installing;
  installingWorker.addEventListener("statechange", function () {
    switch(installingWorker.state){
      case"installed":
        if (navigator.serviceWorker.controller && window.confirm("An updated version of this page is available, would you like to update?")) {
          window.location.reload();
          return;
        }
        break;
      case "redundant":
        console.error("The installing service worker became redundant.");
        break
      
    }
  });
}

if("serviceWorker" in navigator) {
  navigator.serviceWorker.register("offline-worker.js").then(function (registration) {
    console.log("offline worker registered");
    registration.addEventListener("updatefound", updateFound);
  });
}

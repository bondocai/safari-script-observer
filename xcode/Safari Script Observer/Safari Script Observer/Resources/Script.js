// Called by ViewController every second with the extension's state, and whether
// it was off earlier while this window was open (then it has just been turned on,
// and the window is about to close and hand over to Safari's setup page).
function show(enabled, justTurnedOn) {
    const known = typeof enabled === "boolean";
    document.getElementById("off").hidden = !known || enabled;
    document.getElementById("handover").hidden = !(enabled && justTurnedOn);
    document.getElementById("on").hidden = !(enabled && !justTurnedOn);
    document.getElementById("unknown").hidden = known;
}

const send = message => webkit.messageHandlers.controller.postMessage(message);
document.getElementById("open-settings").addEventListener("click", () => send("open-preferences"));
document.getElementById("quit").addEventListener("click", () => send("quit"));

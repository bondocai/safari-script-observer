const form = document.querySelector("form");
const result = document.querySelector("#result");
form.addEventListener("submit", event => event.preventDefault());

document.querySelector("#routine").onclick = async () => {
  await fetch("/asset");
  result.textContent = "Loaded a routine asset. No destination change occurred.";
};

function changeDestination(destination) {
  form.action = "/login";
  setTimeout(() => {
    form.action = destination;
    result.textContent = "Changed the destination to " + destination + ". No form was submitted.";
  }, 50);
}

document.querySelector("#expected").onclick = () => changeDestination("https://identity.example");
document.querySelector("#unexpected").onclick = () => changeDestination("https://unexpected.example");

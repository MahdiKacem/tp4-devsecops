const status = document.querySelector("#status");
const button = document.querySelector("#check-status");

button.addEventListener("click", async () => {
  status.textContent = "Application prête.";
});

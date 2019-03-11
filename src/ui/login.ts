document.addEventListener("DOMContentLoaded", () => {
	const submitButtons = document.querySelectorAll('input[type="submit"]') as NodeListOf<HTMLInputElement>;
	const forms = document.getElementsByTagName("form");

	// Disable submit buttons when clicked
	for (let i = 0; i < forms.length; i++) {
		forms[i].addEventListener("submit", () => {
			for (let j = 0; j < submitButtons.length; j++) {
				submitButtons[j].disabled = true;
			}
		});
	}
	// Navigate between login and sign up
	let loginForm = document.getElementById("login") as HTMLFormElement;
	let signupForm = document.getElementById("signup") as HTMLFormElement;
	document.getElementById("signup-link")!.addEventListener("click", () => {
		loginForm.classList.remove("active");
		signupForm.classList.add("active");
	});
	document.getElementById("login-link")!.addEventListener("click", () => {
		signupForm.classList.remove("active");
		loginForm.classList.add("active");
	});
});

declare const webauthnJSON: typeof import("@github/webauthn-json");

namespace Login {

	const carousel = document.querySelector(".carousel") as HTMLDivElement;
	const errorBlock = document.querySelector(".is-danger > .message-body") as HTMLDivElement;

	function getInput(id: string): HTMLInputElement {
		return document.getElementById(id) as HTMLInputElement;
	}
	const email = getInput("email");
	const firstName = getInput("first-name");
	const preferredName = getInput("preferred-name");
	const lastName = getInput("last-name");
	const password = getInput("password");
	const passwordLogin = getInput("password-login");

	function setUpEnterHandler(input: HTMLInputElement, nextID: number) {
		input.addEventListener("keydown", e => {
			if (e.key === "Enter") {
				let next = document.querySelector(`#step${nextID} .button.next`) as HTMLButtonElement;
				next.click();
			}
		});
	}
	setUpEnterHandler(email, 1);
	setUpEnterHandler(passwordLogin, 1);
	setUpEnterHandler(lastName, 2);
	setUpEnterHandler(password, 3);

	const commonFetchSettings: Partial<RequestInit> = {
		method: "POST",
		credentials: "include",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
		},
	};

	function serializeQueryString(data: object): string {
		return Object.keys(data).map(key => {
			return encodeURIComponent(key) + "=" + encodeURIComponent(data[key]);
		}).join("&");
	}

	function setUpStep(step: number) {
		let back = document.querySelector(`#step${step} .button.back`) as HTMLButtonElement | null;
		let next = document.querySelector(`#step${step} .button.next`) as HTMLButtonElement | null;

		if (back && step > 1) {
			back.addEventListener("click", () => {
				errorBlock.textContent = "";
				carousel.classList.remove("step" + step);
				carousel.classList.add("step" + (step - 1));
			});
		}
		if (next) {
			next.addEventListener("click", async () => {
				try {
					next.disabled = true;
					// Do input validation
					if (step === 1) {
						let emailRegex = /\S+@\S+\.\S+/;
						if (!emailRegex.test(email.value)) {
							errorBlock.textContent = "Please input a valid email";
							return;
						}

						if (!passwordLogin.value) {
							let { type } = await fetch(`/api/login-type?email=${encodeURIComponent(email.value.trim())}`).then(response => response.json());
							if (["gatech", "google", "github", "facebook"].includes(type)) {
								window.location.href = `/auth/${type}`;
								return;
							}
							if (type === "local") {
								let passwordContainer = document.getElementById("hidden-password");
								passwordContainer.classList.remove("hidden");
								passwordContainer.classList.add("shown");
								passwordLogin.focus();
								return;
							}
							await fetch(`/api/signup-data`, {
								...commonFetchSettings,
								body: serializeQueryString({ email: email.value.trim() })
							});
						}
						else {
							await fetch(`/auth/login`, {
								...commonFetchSettings,
								body: serializeQueryString({
									email: email.value.trim(),
									password: passwordLogin.value
								})
							});
							window.location.reload();
							return;
						}
					}
					if (step === 2) {
						let firstNameValue = firstName.value.trim();
						let preferredNameValue = preferredName.value.trim();
						let lastNameValue = lastName.value.trim();
						if (!firstNameValue || !lastNameValue) {
							errorBlock.textContent = "Please enter your first and last name. We use it to identify you online and at events!"
							return;
						}
						await fetch(`/api/signup-data`, {
							...commonFetchSettings,
							body: serializeQueryString({
								firstName: firstNameValue,
								preferredName: preferredNameValue,
								lastName: lastNameValue
							})
						});
					}
					if (step === 3) {
						// User has submitted a password for a local account
						if (!password.value.trim()) {
							errorBlock.textContent = "Please enter a password or sign up using an external service";
							return;
						}
						let firstNameValue = firstName.value.trim();
						let preferredNameValue = preferredName.value.trim();
						let lastNameValue = lastName.value.trim();
						await fetch(`/auth/signup`, {
							...commonFetchSettings,
							body: serializeQueryString({
								email: email.value.trim(),
								firstName: firstNameValue,
								preferredName: preferredNameValue,
								lastName: lastNameValue,
								password: password.value
							})
						});
						window.location.reload();
					}

					if (step === 1 || step === 2) {
						errorBlock.textContent = "";
						carousel.classList.remove("step" + step);
						carousel.classList.add("step" + (step + 1));
					}
				}
				finally {
					next.disabled = false;
				}
			});
		}
	}

	setUpStep(1);
	setUpStep(2);
	setUpStep(3);

	(async () => {
		if (webauthnJSON.supported()) {
			let publicKey = await fetch("/auth/fido2/register").then(response => response.json());
			let credential = await webauthnJSON.create({ publicKey });
			await fetch(`/auth/fido2/register`, {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(credential)
			});
		}
	})().catch(err => console.error(err));
}

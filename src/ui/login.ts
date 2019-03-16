
const carousel = document.querySelector(".carousel") as HTMLMainElement;
const errorBlock = document.querySelector(".is-danger > .message-body") as HTMLDivElement;

const email = document.getElementById("email") as HTMLInputElement;
const username = document.getElementById("name") as HTMLInputElement;
const password = document.getElementById("password") as HTMLInputElement;

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
						errorBlock.textContent = "Please input valid a email";
						return;
					}
					let { type } = await fetch(`/api/login-type?email=${encodeURIComponent(email.value.trim())}`).then(response => response.json());
					if (["gatech", "google", "github", "facebook"].includes(type)) {
						window.location.href = `/auth/${type}`;
						return;
					}
					if (type === "local") {
						return;
					}
				}
				if (step === 2) {
					if (!username.value.trim()) {
						errorBlock.textContent = "Please enter your name. We use it to identify you online and at events!"
						return;
					}
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

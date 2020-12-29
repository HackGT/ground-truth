const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

const carousel = document.querySelector(".carousel");
const errorBlock = document.querySelector(".is-danger > .message-body");

function getInput(id) {
    return document.getElementById(id);
}

const email = getInput("email");
const firstName = getInput("first-name");
const preferredName = getInput("preferred-name");
const lastName = getInput("last-name");
const password = getInput("password");
const passwordLogin = getInput("password-login");

function setUpEnterHandler(input, nextID) {
    input.addEventListener("keydown", e => {
        if (e.key === "Enter") {
            let next = document.querySelector(`#step${nextID} .button.next`);
            next.click();
        }
    });
}

setUpEnterHandler(email, 1);
setUpEnterHandler(passwordLogin, 1);
setUpEnterHandler(lastName, 2);
setUpEnterHandler(password, 3);

const commonFetchSettings = {
    method: "POST",
    credentials: "include",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "CSRF-Token": csrfToken
    },
};

function serializeQueryString(data) {
    return Object.keys(data).map(key => {
        return encodeURIComponent(key) + "=" + encodeURIComponent(data[key]);
    }).join("&");
}

function setError(error) {
    errorBlock.textContent = error;
    if (error != "") {
        errorBlock.scrollIntoView({ behavior: "smooth" });
    }
}

function setUpStep(step) {
    let back = document.querySelector(`#step${step} .button.back`);
    let next = document.querySelector(`#step${step} .button.next`);

    if (back && step > 1) {
        back.addEventListener("click", () => {
            setError("");
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
                    const emailRegex = /\S+@\S+\.\S+/;
                    if (!emailRegex.test(email.value)) {
                        return setError("Please input a valid email");
                    }

                    if (!passwordLogin.value) {
                        let { type } = await fetch(`/api/client/login-type?email=${encodeURIComponent(email.value.trim())}`).then(response => response.json());
                        if (["gatech", "google", "github", "facebook"].includes(type)) {
                            window.location.href = `/auth/${type}`;
                            return;
                        }
                        if (type === "local") {
                            let passwordContainer = document.getElementById("hidden-password");
                            passwordContainer.classList.remove("hidden");
                            passwordContainer.classList.add("shown");
                            passwordLogin.disabled = false;
                            passwordLogin.focus();
                            return;
                        }
                        await fetch(`/api/client/attach-session-data`, {
                            ...commonFetchSettings,
                            body: serializeQueryString({ email: email.value.trim() })
                        });
                    }
                    else {
                        await fetch(`/auth/login`, {
                            ...commonFetchSettings,
                            body: serializeQueryString({
                                email: email.value.trim(),
                                password: passwordLogin.value,
                                "g-recaptcha-response": grecaptcha.getResponse()
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
                        return setError("Please enter your first and last name. We use it to identify you online and at events!");
                    }
                    await fetch(`/api/client/attach-session-data`, {
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
                    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // There is also backend validation
                    if (!password.value.trim()) {
                        return setError("Please enter a password or sign up using an external service");
                    } else if (!passwordRegex.test(password.value)) {
                        return setError("Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, and one number");
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
                    setError("");
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

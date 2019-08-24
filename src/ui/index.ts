namespace Index {
	declare const webauthnJSON: typeof import("@github/webauthn-json");

	const fido2Button = document.getElementById("fido2") as HTMLAnchorElement | null;
	if (fido2Button) {
		fido2Button.addEventListener("click", async () => {
			await attachFIDO2();
		});
	}

	function checkFIDO2Support(): boolean {
		const supported = webauthnJSON.supported();
		if (!supported) {
			alert("FIDO2 is not supported in your browser. Please upgrade to the latest version of Chrome, Firefox, or Edge.");
		}
		return supported;
	}

	async function attachFIDO2() {
		if (!checkFIDO2Support()) return;

		let publicKey = await fetch("/auth/fido2/attach").then(response => response.json());
		try {
			let credential = await webauthnJSON.create({ publicKey });
			await fetch("/auth/fido2/attach", {
				method: "POST",
				credentials: "include",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(credential)
			});
			window.location.reload();
		}
		catch (err) {
			console.error(err);
			alert("Couldn't sign you up with FIDO2. Please try again. (Did you close or cancel the dialog?)");
		}
	}
}

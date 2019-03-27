namespace Admin {
	function setUpHandlers(classname: string, handler: (uuid: string, button: HTMLButtonElement) => Promise<void>) {
		let buttons = document.getElementsByClassName(classname) as HTMLCollectionOf<HTMLButtonElement>;
		for (let i = 0; i < buttons.length; i++) {
			buttons[i].addEventListener("click", async e => {
				let button = e.target as HTMLButtonElement;
				button.disabled = true;
				try {
					await handler(button.dataset.uuid, button);
				}
				finally {
					button.disabled = false;
				}
			});
		}
	}

	function serializeQueryString(data: object): string {
		return Object.keys(data).map(key => {
			return encodeURIComponent(key) + "=" + encodeURIComponent(data[key]);
		}).join("&");
	}

	interface APIResponse {
		success?: boolean;
		error?: string;
	}

	async function sendRequest(url: string, data?: object) {
		let options: RequestInit = {
			method: "POST",
			credentials: "include"
		};
		if (data) {
			options = {
				...options,
				headers: {
					"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
				},
				body: serializeQueryString(data)
			};
		}

		let response: APIResponse = await fetch(url, options).then(response => response.json());
		if (!response.success) {
			alert(response.error);
		}
		else {
			window.location.reload();
		}
	}

	setUpHandlers("rename", async (uuid, button) => {
		let name = prompt("New name:", button.dataset.name);
		if (!name) return;

		await sendRequest(`/api/admin/app/${uuid}/rename`, { name: name.trim() });
	});
	setUpHandlers("edit-redirects", async (uuid, button) => {
		let uris = prompt("Redirect URIs (comma separated):", button.dataset.uris);
		if (!uris) return;

		await sendRequest(`/api/admin/app/${uuid}/redirects`, { redirectURIs: uris.trim() });
	});
	setUpHandlers("regenerate-secret", async (uuid, button) => {
		if (!confirm("Are you sure you want to regenerate this app's client secret? This will require reconfiguring this application with the newly generated secret.")) return;

		await sendRequest(`/api/admin/app/${uuid}/regenerate`);
	});
	setUpHandlers("remove", async (uuid, button) => {
		if (!confirm("Are you sure you want to delete this app?")) return;

		await sendRequest(`/api/admin/app/${uuid}/delete`);
	});

	let addApplicationButton = document.getElementById("add-application") as HTMLButtonElement;
	addApplicationButton.addEventListener("click", async () => {
		try {
			addApplicationButton.disabled = true;
			let nameField = document.getElementById("name") as HTMLInputElement;
			let redirectURIsField = document.getElementById("redirect-uris") as HTMLInputElement;

			let name = nameField.value.trim();
			let redirectURIs = redirectURIsField.value.trim();
			if (!name) {
				alert("Application name cannot be blank");
				return;
			}
			if (!redirectURIs) {
				alert("Application must have at least one redirect URI");
				return;
			}

			await sendRequest("/api/admin/app", { name, redirectURIs });
		}
		finally {
			addApplicationButton.disabled = false;
		}
	});

	let addAdminButton = document.getElementById("admin-promote") as HTMLButtonElement;
	addAdminButton.addEventListener("click", async () => {
		let emailField = document.getElementById("admin-email") as HTMLInputElement;
		try {
			addAdminButton.disabled = true;
			let email = emailField.value.trim();
			if (!email) return;

			await sendRequest("/api/admin/add", { email });
		}
		finally {
			emailField.value = "";
			addAdminButton.disabled = false;
		}
	});

	setUpHandlers("delete-admin", async (uuid, button) => {
		if (!confirm("Are you sure you want to revoke admin privileges from this user?")) return;

		await sendRequest("/api/admin/remove", { email: button.dataset.email });
	});
}

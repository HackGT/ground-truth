
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

setUpHandlers("rename", async (uuid, button) => {
	let name = prompt("New name:", button.dataset.name);
	if (!name) return;

	let response: APIResponse = await fetch(`/api/admin/app/${uuid}/rename`, {
		method: "POST",
		credentials: "include",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
		},
		body: serializeQueryString({ name: name.trim() })
	}).then(response => response.json());

	if (!response.success) {
		alert(response.error);
	}
	else {
		window.location.reload();
	}
});
setUpHandlers("edit-redirects", async (uuid, button) => {
	let uris = prompt("Redirect URIs (comma separated):", button.dataset.uris);
	if (!uris) return;

	let response: APIResponse = await fetch(`/api/admin/app/${uuid}/redirects`, {
		method: "POST",
		credentials: "include",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
		},
		body: serializeQueryString({ redirectURIs: uris.trim() })
	}).then(response => response.json());

	if (!response.success) {
		alert(response.error);
	}
	else {
		window.location.reload();
	}
});
setUpHandlers("regenerate-secret", async (uuid, button) => {
	let response: APIResponse = await fetch(`/api/admin/app/${uuid}/regenerate`, {
		method: "POST",
		credentials: "include"
	}).then(response => response.json());

	if (!response.success) {
		alert(response.error);
	}
	else {
		window.location.reload();
	}
});
setUpHandlers("remove", async (uuid, button) => {
	if (!confirm("Are you sure you want to delete this app?")) return;

	let response: APIResponse = await fetch(`/api/admin/app/${uuid}/delete`, {
		method: "POST",
		credentials: "include"
	}).then(response => response.json());

	if (!response.success) {
		alert(response.error);
	}
	else {
		window.location.reload();
	}
});

let addApplicationButton = document.getElementById("add-application") as HTMLButtonElement;
addApplicationButton.addEventListener("click", async () => {
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

	let response: APIResponse = await fetch(`/api/admin/app`, {
		method: "POST",
		credentials: "include",
		headers: {
			"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
		},
		body: serializeQueryString({ name, redirectURIs })
	}).then(response => response.json());

	if (!response.success) {
		alert(response.error);
	}
	else {
		window.location.reload();
	}
});

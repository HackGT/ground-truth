
function setUpHandlers(classname, handler) {
    let buttons = document.getElementsByClassName(classname);
    for (let i = 0; i < buttons.length; i++) {
        buttons[i].addEventListener("click", async e => {
            let button = e.target;
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

function serializeQueryString(data) {
    return Object.keys(data).map(key => {
        return encodeURIComponent(key) + "=" + encodeURIComponent(data[key]);
    }).join("&");
}

async function sendRequest(url, data) {
    let options = {
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

    let response = await fetch(url, options).then(response => response.json());
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
setUpHandlers("delete-app", async (uuid, button) => {
    if (!confirm("Are you sure you want to delete this app?")) return;

    await sendRequest(`/api/admin/app/${uuid}/delete`);
});
setUpHandlers("delete-scope", async (name, button) => {
    if (!confirm("Are you sure you want to delete this scope?")) return;

    await sendRequest(`/api/admin/scope/delete`, { name });
})

let addApplicationButton = document.getElementById("add-application");
addApplicationButton.addEventListener("click", async () => {
    try {
        addApplicationButton.disabled = true;
        let nameField = document.getElementById("name");
        let redirectURIsField = document.getElementById("redirect-uris");
        let clientType = (document.querySelector(`input[name="client-type"]:checked`)).value;

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

        await sendRequest("/api/admin/app", { name, redirectURIs, clientType });
    }
    finally {
        addApplicationButton.disabled = false;
    }
});

let addScopeButton = document.getElementById("add-scope");
addScopeButton.addEventListener("click", async () => {
    try {
        addScopeButton.disabled = true;

        let name = document.getElementById("scope-name");
        let question = document.getElementById("scope-question");
        let type = document.getElementById("scope-type");
        let icon = document.getElementById("scope-icon");
        let validatorCode = document.getElementById("scope-validator");
        let errorMessage = document.getElementById("scope-error-message");

        await sendRequest("/api/admin/scope", {
            name: name.value,
            question: question.value,
            type: type.value,
            icon: icon.value,
            validatorCode: validatorCode.value,
            errorMessage: errorMessage.value,
        });
    }
    finally {
        addScopeButton.disabled = false;
    }
});

let addAdminButton = document.getElementById("admin-promote");
addAdminButton.addEventListener("click", async () => {
    let emailField = document.getElementById("admin-email");
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
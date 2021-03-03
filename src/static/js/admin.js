const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute("content");

// Navigation tab handlers
const navigationTabs = document.getElementById("admin-navigation").getElementsByTagName("li");

for (let index = 0; index < navigationTabs.length; index++) {
  const currentTab = navigationTabs[index];

  currentTab.addEventListener("click", async e => {
    const tabContents = document.getElementsByClassName("tab-content");
    for (let i = 0; i < tabContents.length; i++) {
      tabContents[i].style.display = "none";
    }

    for (let i = 0; i < navigationTabs.length; i++) {
      navigationTabs[i].classList.remove("is-active");
    }

    document.getElementById(currentTab.dataset.content).style.display = "block";
    currentTab.classList.add("is-active");
  });
}

// If there is a current tab in local storage, set that tab otherwise the first one
const activeTabName = localStorage.getItem("activeTabId");
localStorage.removeItem("activeTabId");
document.getElementById(activeTabName || "admin-tab-1").click();

function setUpHandlers(classname, handler) {
  const buttons = document.getElementsByClassName(classname);
  for (let i = 0; i < buttons.length; i++) {
    buttons[i].addEventListener("click", async e => {
      buttons[i].disabled = true;

      try {
        await handler(buttons[i].dataset.id, buttons[i]);
      } finally {
        buttons[i].disabled = false;
      }
    });
  }
}

function serializeQueryString(data) {
  return Object.keys(data)
    .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`)
    .join("&");
}

async function sendRequest(url, method, data) {
  const options = {
    method,
    credentials: "include",
    headers: {
      "CSRF-Token": csrfToken,
    },
  };

  if (data) {
    options.body = serializeQueryString(data);
    options.headers["Content-Type"] = "application/x-www-form-urlencoded;charset=UTF-8";
  }

  const response = await fetch(url, options).then(response => response.json());
  if (!response.success) {
    alert(response.error);
  } else {
    // Remember current tab on refresh
    const activeTab = document.getElementById("admin-navigation").querySelector("li.is-active");
    localStorage.setItem("activeTabId", activeTab.id);

    window.location.reload();
  }
}

// APPLICATIONS TAB
setUpHandlers("rename", async (id, button) => {
  const name = prompt("New name:", button.dataset.name);
  if (!name) return;

  await sendRequest(`/api/apps/${id}/rename`, "PUT", { name: name.trim() });
});
setUpHandlers("edit-redirects", async (id, button) => {
  const uris = prompt("Redirect URIs (comma separated):", button.dataset.uris);
  if (!uris) return;

  await sendRequest(`/api/apps/${id}/redirects`, "PUT", { redirectURIs: uris.trim() });
});
setUpHandlers("regenerate-secret", async (id, button) => {
  if (
    !confirm(
      "Are you sure you want to regenerate this app's client secret? This will require reconfiguring this application with the newly generated secret."
    )
  )
    return;

  await sendRequest(`/api/apps/${id}/regenerate`, "PUT");
});
setUpHandlers("delete-app", async (id, button) => {
  if (!confirm("Are you sure you want to delete this app?")) return;

  await sendRequest(`/api/apps/${id}`, "DELETE");
});

// Handles hiding and showing secrets on arrow click
const secretArrows = document.getElementsByClassName("secret-arrow");
const secretSpans = document.getElementsByClassName("secret-container");
for (let i = 0; i < secretArrows.length; i++) {
  secretArrows[i].addEventListener("click", async e => {
    secretSpans[i].classList.toggle("is-hidden");

    const arrowIcon = secretArrows[i].children[0];
    arrowIcon.classList.toggle("fa-arrow-right");
    arrowIcon.classList.toggle("fa-arrow-down");
  });
}

const addApplicationButton = document.getElementById("add-application");
addApplicationButton.addEventListener("click", async () => {
  try {
    addApplicationButton.disabled = true;
    const nameField = document.getElementById("name");
    const redirectURIsField = document.getElementById("redirect-uris");
    const clientType = document.querySelector(`input[name="client-type"]:checked`).value;

    const name = nameField.value.trim();
    const redirectURIs = redirectURIsField.value.trim();
    if (!name) {
      alert("Application name cannot be blank");
      return;
    }
    if (!redirectURIs) {
      alert("Application must have at least one redirect URI");
      return;
    }

    await sendRequest("/api/apps", "POST", { name, redirectURIs, clientType });
  } finally {
    addApplicationButton.disabled = false;
  }
});

// SCOPES TAB
setUpHandlers("delete-scope", async (id, button) => {
  if (!confirm("Are you sure you want to delete this scope?")) return;

  await sendRequest(`/api/scopes/${id}`, "DELETE");
});

const addScopeButton = document.getElementById("add-scope");
addScopeButton.addEventListener("click", async () => {
  try {
    addScopeButton.disabled = true;

    const name = document.getElementById("scope-name");
    const question = document.getElementById("scope-question");
    const type = document.getElementById("scope-type");
    const icon = document.getElementById("scope-icon");
    const validatorCode = document.getElementById("scope-validator");
    const errorMessage = document.getElementById("scope-error-message");

    await sendRequest("/api/scopes", "POST", {
      name: name.value,
      question: question.value,
      type: type.value,
      icon: icon.value,
      validatorCode: validatorCode.value,
      errorMessage: errorMessage.value,
    });
  } finally {
    addScopeButton.disabled = false;
  }
});

// USERS TAB
const addMemberButton = document.getElementById("member-add");
addMemberButton.addEventListener("click", async () => {
  const emailField = document.getElementById("member-email");

  try {
    addMemberButton.disabled = true;
    const email = emailField.value.trim();
    if (!email) return;

    await sendRequest(`/api/members`, "POST", { email, member: true });
  } finally {
    addMemberButton.disabled = false;
  }
});

setUpHandlers("delete-admin", async (id, button) => {
  if (!confirm("Are you sure you want to revoke admin privileges from this user?")) return;

  await sendRequest(`/api/members`, "POST", { email: button.dataset.email, admin: false });
});

setUpHandlers("add-admin", async (id, button) => {
  await sendRequest(`/api/members`, "POST", { email: button.dataset.email, admin: true });
});

setUpHandlers("delete-member", async (id, button) => {
  if (
    !confirm(
      "Are you sure you want to remove this member as a user? They will also be removed as an admin if applicable."
    )
  )
    return;

  await sendRequest(`/api/members`, "POST", {
    email: button.dataset.email,
    admin: false,
    member: false,
  });
});

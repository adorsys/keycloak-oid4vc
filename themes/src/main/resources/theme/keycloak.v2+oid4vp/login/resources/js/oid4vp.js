// @ts-check

/**
 * Checks the authentication status periodically.
 *
 * @param {URL} url
 * @param {number} period
 */
export async function checkAuthStatus(url, period) {
  try {
    // Retrieve status
    const response = await fetch(url);
    if (response.status !== 200 && response.status !== 404) {
      throw new Error(`Unexpected response status: ${response.status}`);
    }

    // Parse response payload
    const data = await response.json();

    // Pending request
    if (data.status === "pending") {
      return setTimeout(() => checkAuthStatus(url, period), period);
    }

    // Authentication failed
    if (data.status !== "success") {
      return reportError(response.status, data.error_description);
    }

    // Authentication was successful
    submitForm(data.authorization_code);
  } catch (error) {
    console.error("Error while polling:", error);
    // Retrying
    setTimeout(() => checkAuthStatus(url, period), period);
  }
}

/**
 * Handles submitting the authorization code.
 *
 * @param {string} code
 */
function submitForm(code) {
  document.getElementById("kc-oid4vp-code-input").value = code;
  document.getElementById("kc-oid4vp-completion-form").submit();
}

/**
 * Handles reporting errors to the user.
 *
 * @param {string} message
 * @param {number} httpStatus
 */
function reportError(httpStatus, message) {
  if (httpStatus == 404) {
    console.warn("Session expired. Please reload to retry.");
  } else {
    console.error(message);
  }
}

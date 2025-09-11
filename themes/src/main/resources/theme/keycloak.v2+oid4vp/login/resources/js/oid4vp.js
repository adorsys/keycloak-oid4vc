// @ts-check

/**
 * Checks the authentication status periodically.
 *
 * @param {URL} url
 * @param {number} period
 */
export async function checkAuthStatus(url, period) {
  try {
    const response = await fetch(url);
    if (response.status !== 200) {
      throw new Error(`Unexpected response status: ${response.status}`);
    }

    const data = await response.json();
    if (data.status === "pending") {
      return setTimeout(() => checkAuthStatus(url, period), period);
    }

    if (data.status === "success") {
      document.getElementById("code").value = data.authorization_code;
      document.getElementById("kc-oid4vp-completion-form").submit();
    } else if (data.status === "error") {
      console.error(`${data.error}: ${data.error_description}`);
    }
  } catch (error) {
    console.error("Error while polling:", error);
  }
}

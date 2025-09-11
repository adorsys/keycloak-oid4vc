<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false displayInfo=false; section>
<!-- template: login-oid4vp-wallet.ftl -->

    <#if section = "header">
        Scan the QR code
    <#elseif section = "form">
        <p>${oid4vp.authContext.authReqQrCode}</p>

        <form action="${oid4vp.loginActionUrl}"
              id="kc-oid4vp-completion-form"
              method="post"
              style="display:none;">
            <input type="hidden" id="code" name="code" value="" />
        </form>

        <script type="module">
            import { checkAuthStatus } from "${url.resourcesPath}/js/oid4vp.js";
            checkAuthStatus("${oid4vp.authContext.authStatusUrl}", 2500);
        </script>
    </#if>

</@layout.registrationLayout>

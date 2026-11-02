// ===== REAL E-MAIL SENDING (EmailJS, free plan: 200 e-mails / month) =====
// Without these 3 values the site works in "simulation" mode (the e-mail is shown on the page).
// To receive the reset code in your REAL Gmail inbox:
//   1. Create a free account on https://www.emailjs.com
//   2. "Email Services" -> Add new service -> Gmail -> connect your Gmail account -> copy the Service ID
//   3. "Email Templates" -> Create new template. Settings tab: "To Email" = {{to_email}}.
//        Subject : Reset your password - {{app_name}}
//        Content : Hello {{to_name}}, your password reset code is: {{code}}  (valid for 10 minutes).
//      Save it and copy the Template ID
//   4. "Account" -> General -> copy the Public Key
//   5. Paste the 3 values below, save the file, reload login.html (the page must be opened from a web address
//      or from the file; EmailJS accepts both).
window.EMAILJS_CONFIG = {
  serviceId: "",     // example: "service_ab12cde"
  templateId: "",    // example: "template_x9y8z7w"
  publicKey: ""      // example: "AbCdEfGhIjKlMnOpQ"
};
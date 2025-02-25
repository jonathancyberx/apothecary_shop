# Application Security Engineer Challenge - Vulnerability Report Findings & Remediation

Author: Jonathan Ayodele ayodelejona@gmail.com

This report details the security vulnerabilities identified in the Apothecary shop web application. The assessment uncovered multiple vulnerabilities that pose significant risks to data integrity, confidentiality, and user security. Each vulnerability is documented with a description, exploitation method, potential impact assessment, proof of concept (PoC), and recommended remediation.

## 1. SQL Injection (SQLi) in Potion Search Box.

### Descrition

The potion search functionality is vulnerable to SQL Injection (SQLi). The application constructs database queries using unsanitized user input, allowing attackers to manipulate the underlying SQL commands to extract sensitive data or alter the database.

### Impact

1. Unrestricted access to database records: Attackers can enumerate potion records beyond the intended seven on display, to reveal an additional 5 records

2. Potential for authentication bypass (if used in login queries).

3. Data exfiltration and modification.

4. Potential execution of administrative commands on the database.

### Steps to Reproduce

1. Login and navigate to the potion search box.

2. Enter the following payload:

```bash
' OR '1'='1
```
**Result:** It reveals additional 5 potion entries, cofirming SQLi

### Remediation

1. Use parameterized queries or Elixir’s Ecto Query API to prevent SQL injection.
2. Validate and sanitize user input before processing database queries.

## 2. Stored Cross-Site Scripting (XSS) in Review Box.

### Descrition

The application does not sanitize user-submitted reviews, allowing JavaScript execution when the review is displayed. This enables Stored XSS, where the payload persists in the database and executes when retrieved.

### Impact

1. Malicious JavaScript executes in users' browsers when viewing affected potion pages which can lead to defacement of the application UI.
2. Attackers can steal authentication cookies via `document.cookie`, hijack sessions, or perform actions on behalf of users.


### Steps to Reproduce

1. Log in and navigate to  a potion’s review section by clicking on a potion.

2. Enter the following payload:

```bash
<script>alert('Potion Hacked')</script>
```
**Result:** Refresh the page, the script executes in the browser. When another user visits the potion page, the injected script also executes.

### Remediation

1. Implement a Content Security Policy (CSP) to prevent inline JavaScript execution.
2. Escape user-generated content before rendering: Use Phoenix’s built-in html_escape/1 function to sanitize user input
```bash
<%= Phoenix.HTML.html_escape(review.body) %>
```

## 3. Insecure Direct Object Reference (IDOR) in Review Submission.

### Descrition

The review submission form allows a user to modify the user_id parameter (email), enabling unauthorized modification of other users' reviews and impersonating other users.
The hidden email field (review[email]) is prefilled with jonathantes2t@gmail.com:
This suggests that the app trusts this email field without validating it on the backend.

### Impact

1. Attackers can submit reviews impersonating other users.
2. Could lead to reputation manipulation or fraudulent content submissions.
3. Potential for business logic abuse.


### Steps to Reproduce

1. Log in and navigate to  a potion’s review section by clicking on a potion.

2. Using Developer Tools (Press F12) or right click and select inspect, go to the elements tab and search for the email field. 
3. Double click and modify the value

```bash
<input id="review_email" name="review[email]" type="hidden" value="enter victim user email">
```
4. Submit the review.

>**NOTE:** Email must be a registered user

**Result:** The targeted user's review is updated without their consent, confirming IDOR.

### Remediation

1. Enforce server-side authorization checks to validate ownership before updating review records.
```bash
if review.user_id == current_user.id do
  # Allow update
else
  # Return unauthorized error
end
```
2. Derive the user's email from the session instead of allowing client-side input


## Vulnerability Fix: Stored XSS in Review Box

### Fix Implemented
The stored XSS vulnerability was mitigated by escaping user input before rendering reviews. I also implemented a Content Security Policy (CSP) to block inline JavaScript execution.

### Code Changes
I modified the review display logic in the code:
in the following file `lib/apothecary_web/templates/potion/show.html.heex`

from 
```bash
<div><%= raw (review.body) %></div>
```
to 

```bash
<div><%= Phoenix.HTML.escape(review.body) %></div>
```
Phoenix provides Phoenix.HTML.html_escape/1 for escaping user input.

Additionall, I implemented Content Security Policy headers as follows
in the `lib/apothecary_web/endpoint.ex` file

```bash
plug :put_secure_browser_headers

defp put_secure_browser_headers(conn, _opts) do
  conn
  |> Plug.Conn.put_resp_header(
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
  )
end
```
This helps prevent XSS by blocking inline scripts and restricting script sources.



# SAST Tool Integration in CI Pipeline

To proactively detect detect these vulnerabilities identified above, and prevent them from reoccurring, a Static Application Security Testing (SAST) tool should be integrated into the CI/CD pipeline.

## Tool Recommendation
1. Brakeman (for Elixir)
2. SonarQube (supports Elixir through plugins)
3. Bandit (for detecting common security issues)

## Implementation Steps
Modify the CI/CD configuration to run SAST checks on every pull request.

1. Add SAST tool to the CI configuration (e.g., GitHub Actions, GitLab CI).
2. Configure rules to detect SQLi, XSS, and IDOR patterns.
3. Block builds that introduce high-severity vulnerabilities, allow manual security review if necessary.
4. Regularly update rules and signatures to detect new threats.
5. Conduct periodic manual penetration testing alongside automated scans.

## Example GitHub Actions Integration
Add a new workflow file (`.yml`)

```bash
name: SAST Scan
on: push
jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Run Brakeman for Elixir
        run: mix brakeman.scan
```


## Challenges Encountered
### Ubuntu Server and Dependency Installation Issues:

- Setting up the required environment on an Ubuntu server presented challenges, particularly with installing necessary dependencies.
- Some packages had missing dependencies, requiring manual resolution. Additionally, configuring Elixir, Phoenix, and PostgreSQL correctly to ensure the application ran smoothly took extra effort.
- Troubleshooting compatibility issues and resolving package installation errors added unexpected delays to the process.

### Content Security Policy (CSP) Implementation Challenge:

- I attempted to enforce a Content Security Policy (CSP) to prevent inline scripts from executing and display an alert message when a violation occurred. However, ensuring the correct nonce was generated and passed to all necessary places proved complex.
- Properly integrating this into Phoenix LiveView without interfering with existing functionality required an understanding of how LiveView dynamically injects and updates content.
- While I aimed to block unauthorized scripts and display a clear "Not Allowed" message, making the implementation fully operational required additional troubleshooting beyond the available time.

## Conclusion
This assessment identified three critical vulnerabilities: SQL Injection, Stored XSS, and IDOR. A fix was implemented for the Stored XSS issue, and recommendations were provided for securing the application.
The identified vulnerabilities pose significant security risks and should be addressed immediately. Implementing the recommended fixes will improve the application's security posture. Additionally, integrating a SAST tool in the CI/CD pipeline will prevent future vulnerabilities by mitigating security flaws, and enhance security posture by detecting vulnerabilities in the development lifecycle.

## Signed
Jonathan Ayodele
ayodelejona@gmail.com
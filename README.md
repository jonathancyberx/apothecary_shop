# Application Security Engineer Challenge

Hello and welcome to the Application Security Engineer Challenge!

This Git repository is an Elixir/Phoenix application with four vulnerabilities. As part of this challenge, you'll need to find and document at least **three** of them. Then, pick **one** of the vulnerabilities you found and fix it. You can find vulnerabilities in:

1. The application's main potion search box.

2. A potion's review box.

3. A potion's review form.

4. The User's bio form in the Settings page.

After you're done, answer the follow-up question:

>How you would implement a SAST tool as part of this application's Continuous Integration pipeline to automatically detect these vulnerabilities?

## Deliverable
Create a file named `ANSWERS.md` and document the **three** vulnerabilities you found. Then, answer our follow-up question.

Make the changes to the code required to fix **one** of the vulnerabilities you found and commit your changes to the Git repository as you go. Make sure to add meaningful commit messages.

Once you're done, archive the Git repository and send it back to us as a reply to the original challenge e-mail.

# Running the application

## Setup
Make sure to install [asdf](https://asdf-vm.com/guide/getting-started.html), it's the easiest way to get the specific Elixir and Erlang versions installed.

Also install a recent version of PostgreSQL. We tested PostgreSQL 14.9, the version available in Ubuntu 22.04's package repository and it works fine, but PostgreSQL 14 or 15 should work. 

After you have both, install the Erlang and Elixir asdf plugins:

```bash
asdf plugin install elixir
asdf plugin install erlang
```

Then have asdf install the required versions for this repository (make sure to run the following with the current repository as the current working directory)

```
asdf install
```

This should install Erlang 25.3 and Elixir 1.13.

Set a default password for the `postgres` user so the application can connect to your PostgreSQL server while in development mode.

```
# This will open a Postgres SQL shell
sudo -u postgres psql

# Run the following SQL command to set the password
alter user postgres with encrypted password 'postgres';
```

## How to develop

This command creates the application database, migrates its schema to the latest version and runs seeds for test data
```bash
mix ecto.setup
```

Make sure to reply with 'y' when Mix asks you if it should install Hex.

This command starts the application on http://localhost:4000
```bash
mix phx.server
```
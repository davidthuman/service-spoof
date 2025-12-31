# AI Assisted Coding

I am going to try out Claude Code and more generally AI-assisted features.

I have previously developed with GitHub's CoPilot (for a very short time), but I did not really dive in deep or really let the AI free. I also was not in the position, as a junior developers, to stunt my learning by allowing an AI to do a percentage of my coding.

Add contributions made by Claude Code will have the commit author as Claude (using the `--author "Claude <noreply@anthropic.com>"` option on the `git commit` command).

## How I Will Act

I do want to remain in the development process, both to adjust any plans or code and so I can fully understand everything that is going on within the project. I do not want to "vibe-code".

## The Start (AI)

I already has a very simple Golang program that spoofed an Apache web-servers's 400 response page. I was able to log / dump the request.

I told Claude my overall goal for this project, it asked some questions, I answered, and then it went off. After the code generation and a couple compiler errors, it was able to build and run the program for some small testing.

## After AI Generation (Human)

After a plan and code is generating, I will commit the AI generated code. I will then go and review this code to fully understand it and make manual adjustments as I see fit.\

I am going to create a GenericService type so any configured service with any given name can be loaded and used. The current hard-coded services (WordPress, Apache2, nginx, IIS) have no differences except for that the services are named differently. All differences are reflected in the YAML configuration, which gives no special configuration parameters for these services. With the GenericService, I will be replacing the other service types.

There is also an error return from the new service function, but currently is can only return `nil`.

It also implement un-necessary private fields for service and a getter function for each field. While getters and setters have there place (validation, logging, syncronization), there is currently no reason to implement them (adding complexity now in-case of future features later, i.e. pre-mature optimization).

I also don't know why, but it likes to include the function or struct name in the comments above its definition. However, after looking at other Golang projects, I see that this is common.

When the service is handling the request, and if there is a HTML template to serve, if the read file operation fails, it returns the error via the HTTP response. I am unsure if we want this, as it will expose information about the system. Should it just return a generic 500 error message and log the error for the admin to note.

## Database Migrations (AI)

For initializing the database, the AI started with just having the SQL commands as a string in Go and initialized the database on start-up (`CREATE TABLE IF NOT EXISTS`). This is fine for the start of the project (make it work, make it right, make it fast), but I would like to change the database schema as the project develops.

I asked the AI to use the common [golang-migrate](https://github.com/golang-migrate/migrate) project for database migrations.

## JA4 Fingerprint (Human)

To get a better understanding of the clients that could be accessing these spoofed services, I wanted to implement [JA4 fingerprinting](https://foxio.io/ja4).

## JA4 Fingerprint (Human)

To get a better understanding of the clients that could be accessing these spoofed services, I wanted to implement [JA4 fingerprinting](https://foxio.io/ja4).

My implement works as follows:

- For each service / port used, a `net.Listener` is created to listen for TCP connects on the port. This listener is wrapped to augment the `Accept` function of the listener to create a custom `TlsClientHelloConn` with an augmented `Read` function that will parse the incoming bytes for a complete ClientHello message that can be parsed for the JA4 fingerprint.
- The `ConnContext` parameter on each `http.Server` is set to a function that pulled the parsed fingerprint from the `net.Conn` structure.
- The database logger gets the fingerprint value from the request context.
- A `fingerprint` column was added to the `request_logs` table.

## Claude Code Implementation of JA4 Fingerprinting

I asked Claude Code to do that following while on the same [base commit for my implementation](https://github.com/davidthuman/service-spoof/commit/9e3435ec9529321d51b64629766da405cda800a9).

> I would like you to implement the JA4 fingerprint into the request data that we capture. That following features should be includes:
> 
> - Full JA4 fingerprint parsing from TLS Client Hello messages
> - Connection-level interception to capture raw TLS handshake bytes
> - JA4 fingerprints stored in database with indexed queries
> - Integration with request logging middleware
> - Proper TLS version mapping, GREASE filtering, and hash truncation

With proper planning it produced the following implementation.

- Added JA4 fingerprint and component columns to the `request_logs` table.
- Implemented an in-memory key-value data store `JA4Store` so request loggers / handlers can get the JA4 fingerprint that has been parsed for its associated request. The key for the store is the request's remote address
- Creates a custom `tls.Config` configured with the certificate key pairs, and a `GetConfigForClient` function for being able to capture the Client Hello message
- Creates a JA4 fingerprint parser that takes in a `*tls.ClientHelloInfo` structure.

Critques of the Implementation

- JA4 fingerprint parser using the `tls.ClientHelloInfo` does not provide all the data necessary to generate the real fingerprint
  - The implementation does note that certain fingerprint features are approximate without parsing the raw ClientHello message
- The in-memory key-value data store to pass the parsed JA4 fingerprint to the associated HTTP request handler / logger seems over-engineered.

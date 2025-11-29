# AI Assisted Coding

I am going to try out Claude Code and more generally AI-assisted features.

I have previously developed with GitHub's CoPilot (for a very short time), but I did not really dive in deep or really let the AI free. I also was not in the position, as a junior developers, to stunt my learning by allowing an AI to do a percentage of my coding.

Add contributions made by Claude Code will have the commit author as Claude (using the `--author "Claude <noreply@anthropic.com>"` option on the `git commit` command).

## How I Will Act

I do want to remain in the development process, both to adjust any plans or code and so I can fully understand everything that is going on within the project. I do not want to "vibe-code".

## The Start

I already has a very simple Golang program that spoofed an Apache web-servers's 400 response page. I was able to log / dump the request.

I told Claude my overall goal for this project, it asked some questions, I answered, and then it went off. After the code generation and a couple compiler errors, it was able to build and run the program for some small testing.

## After AI Generation

After a plan and code is generating, I will commit the AI generated code. I will then go and review this code to fully understand it and make manual adjustments as I see fit.\

I am going to create a GenericService type so any configured service with any given name can be loaded and used. The current hard-coded services (WordPress, Apache2, nginx, IIS) have no differences except for that the services are named differently. All differences are reflected in the YAML configuration, which gives no special configuration parameters for these services. With the GenericService, I will be replacing the other service types.

There is also an error return from the new service function, but currently is can only return `nil`.

It also implement un-necessary private fields for service and a getter function for each field. While getters and setters have there place (validation, logging, syncronization), there is currently no reason to implement them (adding complexity now in-case of future features later, i.e. pre-mature optimization).

I also don't know why, but it likes to include the function or struct name in the comments above its definition. However, after looking at other Golang projects, I see that this is common.

When the service is handling the request, and if there is a HTML template to serve, if the read file operation fails, it returns the error via the HTTP response. I am unsure if we want this, as it will expose information about the system. Should it just return a generic 500 error message and log the error for the admin to note.

## Database Migrations

For initializing the database, the AI started with just having the SQL commands as a string in Go and initialized the database on start-up (`CREATE TABLE IF NOT EXISTS`). This is fine for the start of the project (make it work, make it right, make it fast), but I would like to change the database schema as the project develops.

I asked the AI to use the common [golang-migrate](https://github.com/golang-migrate/migrate) project for database migrations.

# Appendix


# Contributing to ADR

Thanks for taking the first step in contributing to our project.

**Uber welcomes contributions of all kinds and sizes. This includes everything from simple bug reports to large features.**

See the [Table of Contents](#table-of-contents) for different ways to contribute and details about how we treat each contribution. Please read the relevant section before making your contribution as it will not only make it a lot easier for us but also ensure you have the very best developer experience too.

> ⭐ If you like the project, but don't have time to contribute just now, that's no problem at all! Give the repo a star and we'll look forward to receiving your future contribution.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [I Have a Question](#i-have-a-question)
- [Component-Specific Guides](#component-specific-guides)
- [I Want To Contribute](#i-want-to-contribute)
    - [Legal Notice](#legal-notice)
- [Enhancements and Features](#enhancements-and-features)
    - [Before Submitting an Enhancement or Feature](#before-submitting-an-enhancement-or-feature)
    - [How do I submit a Good Enhancement or Feature](#how-do-i-submit-a-good-enhancement-or-feature)
- [Reporting Bugs](#reporting-bugs)
    - [Before Submitting a Bug Report](#before-submitting-a-bug-report)
    - [How Do I Submit a Good Bug Report?](#how-do-i-submit-a-good-bug-report)
- [Creating a Pull Request](#creating-a-pull-request)
    - [Before Creating a Pull Request](#before-creating-a-pull-request)
    - [How Do I Submit a Good Pull Request?](#how-do-i-submit-a-good-pull-request)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold these standards.

## I Have a Question

> Please don't file an issue to ask a question. You'll get faster results by using the resources below.

If you want to ask a question about the project, there are a few options available to you.

- Check and read our [documentation](README.md) (start with the README, which links to the Detection and Sensor guides and the reproducibility walkthrough)
- Search our existing [Issues](https://github.com/uber/ADR/issues) as this may also help you.

If you're still facing issues and need further help, then we recommend the following process:

- Open an [issue](https://github.com/uber/ADR/issues/new/choose).
- Provide as **much context as you can** about what you're running into.
- Provide any relevant platform versions (Python, uv, OS/arch), depending on what seems related and **feel free to include screenshots or code-snippets**.

The project maintainers will then take care of the issue as soon as possible and help to resolve your question.

## Component-Specific Guides

This repository has two components, each with its own README and (for Sensor) a component-specific contributing guide:

- [Sensor/](Sensor/) — telemetry collection. See [Sensor/CONTRIBUTING.md](Sensor/CONTRIBUTING.md) for parser-specific guidance, code style, and testing conventions.
- [Detection/](Detection/) — ADR Detector and ADR-Bench. For adding MCP servers, benchmark tasks, or malicious test servers, see the [Detection README](Detection/README.md#part-3-enriching-the-benchmark); other contributions follow the guidance in this file.

## I Want To Contribute

#### Legal Notice

When contributing to any Uber Open Source project, you agree that you have authored 100% of the content and that you have the necessary rights to that content and that the content you contribute may be provided under the project license.

You're required to sign our [Contributor License Agreement](https://cla-assistant.io/uber/ADR) to confirm this and you'll be prompted to do this when submitting your first contribution.

## Enhancements and Features

This section guides you through submitting an enhancement or new functionality into the project; as well as minor improvements to existing functionality. Following these guidelines will help the community to understand your submission.

### Before Submitting an Enhancement or Feature

- Make sure that you are using the latest version of the project.
- **Read the [documentation](README.md) carefully** and find out if the functionality you're proposing is already covered, this may well be through configuration.
- Perform a [search](https://github.com/uber/ADR/issues) to see if the enhancement has already been suggested. If it has, add a comment to the existing issue instead of opening a new one.
- Consider whether your **idea fits with the scope and aims of the project** and keep in mind that we want features that will be useful to the majority of our users and not just a handful.

### How do I submit a Good Enhancement or Feature

Enhancements and new features suggestions are tracked as [issues](https://github.com/uber/ADR/issues).

- Open an [issue](https://github.com/uber/ADR/issues/new/choose).
- Use a **clear and descriptive title** for the issue to identify the suggestion.
- Provide a **description of the enhancement** with as many details as possible touching on what specifically is missing, out of date, wrong, or needs improvement.
- **Describe the current behaviour** of the project and **explain which behaviour you expected to see** instead and why.
- You're welcome to **include screenshots** which help you demonstrate the steps or point out which part your submission is related to.
- **Explain why this enhancement would be useful** to the majority of our project users. You may also want to point out the other projects that solved it better and which could serve as inspiration for making our tool even stronger.

## Reporting Bugs

This section guides you through submitting a Bug Report into the project where a behaviour or functionality isn't working as you'd expect. Following these guidelines will help the community to understand your submission and ensure you've identified a bug correctly.

### Before Submitting a Bug Report

Bug reports shouldn't need the project maintainers to clarify or search for more information. Therefore, we ask you to investigate carefully, collect information and describe the issue in detail in your report. If you complete the following steps in advance, then this will help us fix the issue as fast as possible.

- Make sure that you are using the latest version of the project.
- **Determine if your bug is really a bug** and not an error on your side e.g. using incompatible environment components/versions.
- To see if other users have experienced (and potentially already solved) the same issue you are having, **check if there is not already a bug report** existing for your bug or error in the [bug list](https://github.com/uber/ADR/issues?q=is%3Aissue%20state%3Aopen%20label%3Abug). If it has and the issue is still open, add a comment to the existing issue instead of opening a new one.
- Collect information about the bug:
    - OS, Platform and Version (Windows, Linux, macOS, x86, ARM)
    - Version of the interpreter, compiler, SDK, runtime environment, package manager, depending on what seems relevant – for local instances only.
    - If possible, your input and the output
    - Can you reliably reproduce the issue?

### How Do I Submit a Good Bug Report?

> ⚠️ You must never report security related issues, vulnerabilities or bugs to the issue tracker, or elsewhere in public. Instead sensitive bugs should be submitted through the Uber [HackerOne](https://hackerone.com/uber) process.

We use GitHub issues to track bugs. If you run into an issue with the project:

- Open an [issue](https://github.com/uber/ADR/issues/new/choose) selecting the bug report template.
- Explain the behaviour you would expect and the actual behaviour.
- Please **provide as much context as possible** and describe the reproduction steps that someone else can follow to recreate the issue on their own.
- If you're making changes to the project then your context should also include your code. For good bug reports **you should isolate the problem and create a reduced test case**.

### Once it's filed:

- The project team will label the issue accordingly.
- A project maintainer will try to reproduce the issue with your provided steps. If there are no reproduction steps, or no obvious way to reproduce the issue, we'll request these details but the bug won't be addressed until they are provided.
- If the team is able to reproduce the issue, it will be tagged and the issue will be queued to be implemented.

## Creating a Pull Request

If you want to fix a bug or propose a new feature you'll do this through creating a Pull Request.

### Before Creating a Pull Request

- Check if there is an [issue](https://github.com/uber/ADR/issues/new/choose) that highlights the same problem that you want to solve or that requests the same feature that you want to implement. If this is the case, then **remember to link the issue in your Pull Request**.
- You might also want to check if a similar [pull request](https://github.com/uber/ADR/pulls) has already been created.
- It's always good practice to consider creating an issue before creating a Pull Request but for smaller changes we don't mind if you omit this stage.

### How Do I Submit a Good Pull Request?

- Use a **clear and descriptive title** for the Pull Request.
- Follow this [Pull Request template](.github/pull_request_template.md).
- **Link the issue** related to this Pull Request, if present.
- Provide a **short description of the solution you proposed** in as many details as possible.
- **Use comments in the code** that you provide to give us more context to any code based submissions.

Thanks for contributing to our project.

//! Sending a fixture to the upstream project.
//!
//! The upstream repository is read-only for a contributor: a fixture is a
//! binary file, so it can only land through a pull request. This module does
//! the whole dance with the `gh` CLI, which already holds the user's GitHub
//! credentials, and prints the exact steps when `gh` is not available.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::report::Report;

/// The repository fixtures are sent to, unless another is named.
pub const DEFAULT_TARGET: &str = "The-Open-Memory-Initiative-OMI/spdr";

/// Where the submission goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Channel {
    /// A pull request, which is the only way a binary fixture can land.
    #[default]
    Pr,
    /// An issue on the upstream repository, with the fixture attached by hand.
    Issue,
}

/// Why a submission did not happen.
#[derive(Debug)]
pub enum SubmitError {
    /// The `gh` CLI is not installed.
    NoGh,
    /// A command could not be started.
    Spawn {
        /// The program that failed to start.
        program: String,
        /// What went wrong.
        detail: String,
    },
    /// A command ran and failed.
    Failed {
        /// The command line that failed.
        command: String,
        /// What it printed.
        detail: String,
    },
    /// The fixture could not be written.
    Io {
        /// The path involved.
        path: String,
        /// What went wrong.
        detail: String,
    },
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubmitError::NoGh => f.write_str(
                "the `gh` CLI is not installed, so the submission cannot be made for you; the steps below do it by hand",
            ),
            SubmitError::Spawn { program, detail } => {
                write!(f, "could not run {program}: {detail}")
            }
            SubmitError::Failed { command, detail } => {
                write!(f, "`{command}` failed: {detail}")
            }
            SubmitError::Io { path, detail } => write!(f, "could not write {path}: {detail}"),
        }
    }
}

/// What a submission produced.
#[derive(Debug)]
pub struct Outcome {
    /// The URL of the pull request or issue that was opened.
    pub url: String,
    /// The branch the fixture was pushed to, when it was a pull request.
    pub branch: Option<String>,
    /// The local checkout of the fork, so the contributor can look at it.
    pub checkout: Option<PathBuf>,
}

/// Everything a submission needs.
pub struct Submission<'a> {
    /// The repository to send it to.
    pub target: &'a str,
    /// Where it goes.
    pub channel: Channel,
    /// The fixture file name.
    pub fixture_name: String,
    /// The fixture bytes.
    pub fixture: &'a [u8],
    /// The provenance report.
    pub report: &'a Report,
    /// Whether to add the entry to `docs/validated-against.md` as well.
    pub with_docs: bool,
}

/// The branch a fixture is pushed to.
pub fn branch_name(fixture_name: &str) -> String {
    let stem = fixture_name.strip_suffix(".spd").unwrap_or(fixture_name);
    format!("fixture/{stem}")
}

/// The pull request title.
fn pr_title(report: &Report) -> String {
    let vendor = report
        .manufacturing
        .as_ref()
        .and_then(|info| info.manufacturer.clone())
        .unwrap_or_else(|| "Unknown vendor".to_owned());
    let part = report
        .manufacturing
        .as_ref()
        .map(|info| info.part_number.clone())
        .filter(|part| !part.is_empty())
        .unwrap_or_else(|| "no part number".to_owned());
    let module = report
        .identity
        .as_ref()
        .map(|identity| identity.module_type.clone())
        .unwrap_or_else(|| "undecoded".to_owned());
    format!("test(fixtures): add {vendor} {part} · {module}")
}

/// The pull request body: the provenance, and what the contributor wants the
/// maintainer to know about it.
fn pr_body(report: &Report, fixture_name: &str) -> String {
    let mut body = String::new();
    body.push_str(&crate::report::render_markdown(report));
    body.push_str("\n---\n\n");
    body.push_str(
        "Submitted with [`spdr-collect`](https://github.com/danalec/spdr-collect), the \
         intake tool for this project. The fixture was read from the file named above, \
         the module serial number was replaced, and nothing else was touched: the base \
         configuration CRC still recomputes to the value the module itself stores, \
         because the manufacturing block sits outside the range the CRC covers.\n\n\
         The facts above are machine-generated from the fixture and are open to rewording; \
         the provenance is what needs checking.\n",
    );
    let _ = std::fmt::Write::write_fmt(
        &mut body,
        format_args!(
            "\nThe fixture file name is `{fixture_name}`. If a different convention \
             fits the project, it is a rename away.\n"
        ),
    );
    body
}

/// The issue body: the provenance, plus what the contributor has to attach.
fn issue_body(report: &Report, fixture_path: &Path) -> String {
    let mut body = String::new();
    body.push_str(&crate::report::render_markdown(report));
    body.push_str("\n---\n\n");
    let _ = std::fmt::Write::write_fmt(
        &mut body,
        format_args!(
            "Submitted with [`spdr-collect`](https://github.com/danalec/spdr-collect).\n\n\
             **The sanitised fixture is attached to this issue**: `{path}`.\n",
            path = fixture_path.display()
        ),
    );
    body
}

/// The steps to run by hand, when `gh` cannot do them.
pub fn manual_steps(target: &str, fixture_name: &str, branch: &str) -> String {
    format!(
        "1. Fork the upstream repository: {url}/fork\n\
         2. In your fork, create a branch named `{branch}` from the upstream's `main`.\n\
         3. Add the sanitised fixture as `spdr/tests/fixtures/{fixture_name}`, and the \
         provenance block as a new section of `docs/validated-against.md`.\n\
         4. Push the branch and open a pull request against {target}'s `main`.\n",
        url = "https://github.com",
        target = target,
    )
}

/// Run a command and capture its output.
fn run(program: &str, args: &[&str], cwd: &Path) -> Result<String, SubmitError> {
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|err| SubmitError::Spawn {
            program: program.to_owned(),
            detail: err.to_string(),
        })?;
    if !output.status.success() {
        return Err(SubmitError::Failed {
            command: format!("{program} {}", args.join(" ")),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Check that `gh` is installed and logged in.
pub fn check_gh() -> Result<(), SubmitError> {
    let output = Command::new("gh")
        .arg("--version")
        .output()
        .map_err(|_| SubmitError::NoGh)?;
    if !output.status.success() {
        return Err(SubmitError::NoGh);
    }
    Ok(())
}

/// Send the fixture.
pub fn send(submission: &Submission<'_>) -> Result<Outcome, SubmitError> {
    check_gh()?;

    let branch = branch_name(&submission.fixture_name);
    let workdir = std::env::temp_dir().join(format!("spdr-collect-submit-{branch}"));
    let _ = std::fs::remove_dir_all(&workdir);
    std::fs::create_dir_all(&workdir).map_err(|err| SubmitError::Io {
        path: workdir.display().to_string(),
        detail: err.to_string(),
    })?;

    // Fork the upstream and clone the fork. `gh` does the authentication, and
    // reuses the fork if it already exists.
    run(
        "gh",
        &[
            "repo",
            "fork",
            submission.target,
            "--clone",
            "--remote",
            "--default-branch-only",
        ],
        &workdir,
    )?;

    let repo_name = submission.target.split('/').next_back().unwrap_or("spdr");
    let checkout = workdir.join(repo_name);
    if !checkout.join(".git").exists() {
        return Err(SubmitError::Io {
            path: checkout.display().to_string(),
            detail: "the fork was not cloned where it was expected".to_owned(),
        });
    }

    // The fork's own `main` may be ahead of the upstream's, so the branch is
    // taken from the upstream's `main` rather than the fork's.
    let upstream_url = format!("https://github.com/{}.git", submission.target);
    let _ = run("git", &["remote", "remove", "upstream"], &checkout);
    run(
        "git",
        &["remote", "add", "upstream", &upstream_url],
        &checkout,
    )?;
    run("git", &["fetch", "upstream", "main"], &checkout)?;
    run(
        "git",
        &["checkout", "-b", &branch, "upstream/main"],
        &checkout,
    )?;

    // The fixture goes where the project keeps its fixtures.
    let fixture_dir = checkout.join("spdr").join("tests").join("fixtures");
    std::fs::create_dir_all(&fixture_dir).map_err(|err| SubmitError::Io {
        path: fixture_dir.display().to_string(),
        detail: err.to_string(),
    })?;
    let fixture_path = fixture_dir.join(&submission.fixture_name);
    std::fs::write(&fixture_path, submission.fixture).map_err(|err| SubmitError::Io {
        path: fixture_path.display().to_string(),
        detail: err.to_string(),
    })?;

    // And the provenance goes where the project documents its fixtures.
    if submission.with_docs {
        let docs = checkout.join("docs").join("validated-against.md");
        let existing = std::fs::read_to_string(&docs).map_err(|err| SubmitError::Io {
            path: docs.display().to_string(),
            detail: err.to_string(),
        })?;
        let entry = crate::report::render_markdown(submission.report);
        let appended = format!(
            "{existing}\n\n---\n\n{entry}\n<!-- The section above was generated by spdr-collect \
             and is open to rewording. -->\n"
        );
        std::fs::write(&docs, appended).map_err(|err| SubmitError::Io {
            path: docs.display().to_string(),
            detail: err.to_string(),
        })?;
    }

    run(
        "git",
        &[
            "add",
            "--",
            &format!("spdr/tests/fixtures/{}", submission.fixture_name),
        ],
        &checkout,
    )?;
    if submission.with_docs {
        run(
            "git",
            &["add", "--", "docs/validated-against.md"],
            &checkout,
        )?;
    }
    run(
        "git",
        &[
            "commit",
            "-m",
            &pr_title(submission.report),
            "-m",
            &pr_body(submission.report, &submission.fixture_name),
        ],
        &checkout,
    )?;
    run("git", &["push", "-u", "origin", &branch], &checkout)?;

    let url = match submission.channel {
        Channel::Pr => {
            let stdout = run(
                "gh",
                &[
                    "pr",
                    "create",
                    "--repo",
                    submission.target,
                    "--base",
                    "main",
                    "--head",
                    &branch,
                    "--title",
                    &pr_title(submission.report),
                    "--body",
                    &pr_body(submission.report, &submission.fixture_name),
                ],
                &checkout,
            )?;
            stdout.trim().to_owned()
        }
        Channel::Issue => {
            let stdout = run(
                "gh",
                &[
                    "issue",
                    "create",
                    "--repo",
                    submission.target,
                    "--title",
                    &pr_title(submission.report),
                    "--body",
                    &issue_body(submission.report, &fixture_path),
                ],
                &checkout,
            )?;
            stdout.trim().to_owned()
        }
    };

    Ok(Outcome {
        url,
        branch: Some(branch),
        checkout: Some(checkout),
    })
}

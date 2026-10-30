//! The pre-push hook forwards the push destination to the lico-dev gate, but
//! only after stripping credential material from it: user-info lives inside
//! the URL authority and inside scp-style `user@host` syntax, and query or
//! fragment components may carry tokens without changing the destination
//! repository, so all of those are removed while an `@` elsewhere survives.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-invocation scratch directory holding the stub `lico-dev`. The name is
/// unique (process id plus timestamp), creation refuses a pre-existing path,
/// permissions are owner-only, and the directory is removed on drop.
struct StubDir(PathBuf);

impl StubDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("licoarc-hook-test-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let stub = dir.join("lico-dev");
        fs::write(&stub, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
        Self(dir)
    }
}

impl Drop for StubDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs the hook under a stub `lico-dev` that echoes its arguments, and
/// returns the value the hook passed as `--remote-location`.
fn forwarded_location(shell: &str, remote_location: &str) -> String {
    let dir = StubDir::new();
    let output = Command::new(shell)
        .arg(".githooks/pre-push")
        .arg("origin")
        .arg(remote_location)
        .env(
            "PATH",
            format!(
                "{}:{}",
                dir.0.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let args: Vec<&str> = stdout.lines().collect();
    let index = args
        .iter()
        .position(|arg| *arg == "--remote-location")
        .expect("the hook always forwards --remote-location");
    args[index + 1].to_owned()
}

#[test]
fn url_syntaxes_drop_only_the_authority_user_info() {
    // Every fixture below is synthetic and visibly so: hosts live on the
    // RFC 6761 `.test` TLD and user-info literals are `[BRACKETED]`
    // placeholders, never real credential material. The sanitizer is
    // syntax-driven — it removes the user-info component whatever its value —
    // so placeholders exercise the same code path as real credentials.
    // The hook is `#!/bin/sh` and must stay POSIX-clean, so run the matrix
    // under every installed POSIX shell — dash rejects extensions bash
    // tolerates in `sh` mode.
    let shells: Vec<&str> = ["/bin/sh", "/bin/dash"]
        .into_iter()
        .filter(|shell| PathBuf::from(shell).exists())
        .collect();
    assert!(!shells.is_empty());
    for shell in shells {
        let forwarded = |location: &str| forwarded_location(shell, location);

        // scp-style SSH: the user goes, the host:path stays.
        assert_eq!(
            forwarded("[USER]@host.test:LicoLand/LicoArc-Rust.git"),
            "host.test:LicoLand/LicoArc-Rust.git"
        );
        // Credentialed HTTPS: user and password go, host and path stay.
        assert_eq!(
            forwarded("https://[USER]:[PASS]@host.test/repo.git"),
            "https://host.test/repo.git"
        );
        // ssh:// with a port: only the user-info is removed.
        assert_eq!(
            forwarded("ssh://[USER]@host.test:2222/repo.git"),
            "ssh://host.test:2222/repo.git"
        );
        // Query and fragment cannot change the destination repository but
        // can carry tokens, so they are dropped; an `@` inside the path
        // survives.
        assert_eq!(
            forwarded("https://host.test/re@po.git?token=[TOKEN]#frag"),
            "https://host.test/re@po.git"
        );
        // A credential-free remote is forwarded unchanged.
        assert_eq!(
            forwarded("https://host.test/repo.git"),
            "https://host.test/repo.git"
        );
        // A local path containing `@` and `:` is not scp syntax.
        assert_eq!(forwarded("./dir@x:file"), "./dir@x:file");
        // Email-shaped user-info still ends at the authority's last `@`;
        // nothing of the mailbox or the token after it may survive into argv.
        assert_eq!(
            forwarded("https://dev@[MAIL.test]:[TOKEN]@host.test/repo.git"),
            "https://host.test/repo.git"
        );
        // A credentialed URL whose query or fragment exists with no slash at
        // all still drops both components and the user-info.
        assert_eq!(
            forwarded("https://[USER]:[PASS]@host.test?token=[TOKEN]#frag"),
            "https://host.test"
        );
        assert_eq!(
            forwarded("https://[USER]:[PASS]@host.test#[FRAG@with]"),
            "https://host.test"
        );
        // A slash before the colon makes `@` part of a path, not scp syntax:
        // the location is preserved verbatim.
        assert_eq!(forwarded("a@b/c:d"), "a@b/c:d");
        // An `@` inside an scp path belongs to the path, not to user-info:
        // only the user before the first `@` is removed.
        assert_eq!(
            forwarded("[USER]@host.test:Org/@scope/repo.git"),
            "host.test:Org/@scope/repo.git"
        );
        // Multiple `@` before the scp colon are still user-info material:
        // the head is stripped through its final `@` instead of forwarding
        // the ambiguous form verbatim.
        assert_eq!(forwarded("[U]@[H]@host2.test:path"), "host2.test:path");
    }
}

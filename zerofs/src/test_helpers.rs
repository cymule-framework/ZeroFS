#[cfg(test)]
pub mod test_helpers_mod {
    use zerofs_nfsserve::nfs::nfsstring;
    use zerofs_nfsserve::vfs::AuthContext;

    pub fn filename(s: &[u8]) -> nfsstring {
        nfsstring(s.to_vec())
    }

    pub fn test_auth() -> AuthContext {
        AuthContext {
            uid: 1000,
            gid: 1000,
            gids: vec![],
        }
    }
}

#[cfg(feature = "failpoints")]
pub mod isolated_failpoint {
    use std::future::Future;
    use std::path::PathBuf;

    const CHILD_ENV: &str = "ZEROFS_ISOLATED_FAILPOINT_TEST";
    const CHILD_MARKER_ENV: &str = "ZEROFS_ISOLATED_FAILPOINT_TEST_MARKER";

    #[must_use = "dropping this guard removes the failpoint"]
    pub struct ArmedFailpoint(&'static str);

    pub enum Runtime {
        CurrentThread,
        MultiThread { worker_threads: usize },
    }

    impl Drop for ArmedFailpoint {
        fn drop(&mut self) {
            fail::remove(self.0);
        }
    }

    pub fn arm(name: &'static str, actions: &str) -> ArmedFailpoint {
        fail::cfg(name, actions).unwrap();
        ArmedFailpoint(name)
    }

    /// Run a process-global failpoint scenario in a dedicated child test
    /// process. The completion marker prevents an incorrect `--exact` filter
    /// from passing after executing zero tests.
    pub fn run<F, Fut>(test_name: &'static str, runtime: Runtime, test: F)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        if std::env::var(CHILD_ENV).as_deref() != Ok(test_name) {
            let marker_dir = tempfile::tempdir().unwrap();
            let marker = marker_dir.path().join("completed");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(test_name)
                .arg("--nocapture")
                .env(CHILD_ENV, test_name)
                .env(CHILD_MARKER_ENV, &marker)
                .env_remove("FAILPOINTS")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated failpoint child failed:\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                std::fs::read(&marker).unwrap(),
                b"completed",
                "isolated child exited without executing the failpoint scenario"
            );
            return;
        }

        let marker = PathBuf::from(
            std::env::var_os(CHILD_MARKER_ENV).expect("isolated child marker must be configured"),
        );
        let scenario = fail::FailScenario::setup();
        match runtime {
            Runtime::CurrentThread => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test()),
            Runtime::MultiThread { worker_threads } => tokio::runtime::Builder::new_multi_thread()
                .worker_threads(worker_threads)
                .enable_all()
                .build()
                .unwrap()
                .block_on(test()),
        }
        scenario.teardown();
        std::fs::write(marker, b"completed").unwrap();
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn armed_failpoint_is_removed_during_unwind() {
            run(
                "test_helpers::isolated_failpoint::tests::armed_failpoint_is_removed_during_unwind",
                Runtime::CurrentThread,
                || async {
                    let point = "isolated_failpoint_drop_cleanup";
                    let result = std::panic::catch_unwind(|| {
                        let _armed = arm(point, "return");
                        panic!("exercise failpoint cleanup during unwind");
                    });
                    assert!(result.is_err());
                    assert!(
                        fail::eval(point, |_| ()).is_none(),
                        "failpoint remained armed after panic unwinding"
                    );
                },
            );
        }
    }
}

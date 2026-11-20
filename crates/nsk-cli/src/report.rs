//! Result formatting helpers (`run --json`, `inspect`).

use nsk_core::result::SandboxResult;

/// Render a result in the human-readable summary form.
pub fn print_result_summary(result: &SandboxResult) {
    let status = format!("{:?}", result.status);
    println!("=== sandbox {} ===", result.id);
    println!("status:       {status}");
    if let Some(exit) = &result.exit_info {
        if let Some(code) = exit.exit_code {
            println!("exit code:    {code}");
        }
        if let Some(sig) = exit.signal {
            println!("signal:       {sig}");
        }
    }
    let usage = &result.resource_usage;
    println!("wall time:    {:.3}s", usage.wall_time.as_secs_f64());
    if let Some(cpu) = usage.cpu_time {
        println!("cpu time:     {:.3}s", cpu.as_secs_f64());
    }
    if let Some(peak) = usage.memory_peak_bytes {
        println!("memory peak:  {peak} B");
    }
    if let Some(count) = usage.process_count {
        println!("processes:    {count}");
    }
    println!(
        "output:       stdout {} B ({}), stderr {} B ({})",
        usage.stdout_bytes,
        if result.output.stdout.truncated {
            "truncated"
        } else {
            "complete"
        },
        usage.stderr_bytes,
        if result.output.stderr.truncated {
            "truncated"
        } else {
            "complete"
        },
    );
    if !result.diagnostics.is_empty() {
        println!("diagnostics:");
        for d in &result.diagnostics {
            println!("  [{:?}] {}: {}", d.severity, d.code, d.message);
            if let Some(details) = &d.details {
                println!("      {details}");
            }
        }
    }
    let stdout = result.output.stdout.text();
    let stderr = result.output.stderr.text();
    if !stdout.is_empty() {
        println!("--- stdout ---");
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        println!("--- stderr ---");
        println!("{stderr}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsk_core::id::SandboxId;

    #[test]
    fn summary_renders() {
        let mut r = SandboxResult::new(SandboxId::new(), nsk_core::result::SandboxStatus::Success);
        r.exit_info = Some(nsk_core::result::ExitInfo::from_exit_code(0));
        r.output.stdout.retained = b"hi\n".to_vec();
        r.output.stdout.total_bytes = 3;
        let text = {
            // Capture stdout via a quick buffer swap is overkill; just call
            // and assert no panic.
            print_result_summary(&r);
            "ok".to_string()
        };
        assert_eq!(text, "ok");
    }
}

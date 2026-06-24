fn main() {
    println!("--- Kinetic Grace-Period Escalation Simulation ---");
    println!("Simulating T_steal = T_base * e^(k / delta_t)");
    println!("T_base = 10_000_000 iterations (~10 mins baseline)");
    println!("k = 720 (Decay constant, targeting ~1 month normalization)");
    println!("Assuming an ASIC computing 1 billion iterations per second.\n");

    let t_base: f64 = 10_000_000.0;
    let k: f64 = 720.0; // 720 hours = 30 days
    let asic_speed: f64 = 1_000_000_000.0; // 1B iterations / sec

    let time_points = vec![
        ("1 Hour", 1.0),
        ("12 Hours", 12.0),
        ("1 Day", 24.0),
        ("1 Week", 168.0),
        ("1 Month", 720.0),
        ("1 Year", 8760.0),
    ];

    println!("{:<15} | {:<25} | {:<25}", "Delta T", "T_steal (Iterations)", "Estimated ASIC Time");
    println!("{:-<15}-|-{:-<25}-|-{:-<25}", "", "", "");

    for (label, hours) in time_points {
        let exponent = k / hours;
        let t_steal = t_base * exponent.exp();
        
        let seconds = t_steal / asic_speed;
        let time_string = format_time(seconds);

        if t_steal.is_infinite() {
            println!("{:<15} | {:<25} | {:<25}", label, "Infinity", "Forever");
        } else if t_steal > 1e30 {
            println!("{:<15} | {:<25.2e} | {:<25}", label, t_steal, "> Age of Universe");
        } else {
            println!("{:<15} | {:<25.2e} | {:<25}", label, t_steal, time_string);
        }
    }
}

fn format_time(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{:.2} seconds", seconds)
    } else if seconds < 3600.0 {
        format!("{:.2} minutes", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.2} hours", seconds / 3600.0)
    } else if seconds < 31_536_000.0 {
        format!("{:.2} days", seconds / 86400.0)
    } else if seconds < 31_536_000.0 * 100.0 {
        format!("{:.2} years", seconds / 31_536_000.0)
    } else {
        "> 100 Years".to_string()
    }
}

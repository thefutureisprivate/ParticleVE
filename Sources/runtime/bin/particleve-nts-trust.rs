fn main() -> particleve::common::Result<()> {
    particleve::common::require(
        std::env::args_os().len() == 1,
        "this internal helper takes no arguments",
    )?;
    particleve::systemtrust::nts_sessions()
}

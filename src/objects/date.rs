use rcgen::date_time_ymd;
use time::OffsetDateTime;

#[derive(Debug, Copy, Clone, Default)]
pub struct Date {
    /// flutter_rust_bridge:non_final
    pub year: i32,
    /// flutter_rust_bridge:non_final
    pub month: u8,
    /// flutter_rust_bridge:non_final
    pub day: u8,
}

impl From<Date> for OffsetDateTime {
    fn from(Date { year, month, day }: Date) -> Self {
        date_time_ymd(year, month, day)
    }
}

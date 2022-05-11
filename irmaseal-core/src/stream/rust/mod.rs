pub mod sealer;
pub mod unsealer;

impl From<std::io::Error> for crate::Error {
    fn from(e: std::io::Error) -> Self {
        crate::Error::StdIO(e)
    }
}

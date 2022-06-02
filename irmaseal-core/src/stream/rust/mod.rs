mod sealer;
mod unsealer;

#[doc(inline)]
pub use sealer::seal;

#[doc(inline)]
pub use unsealer::Unsealer;

impl From<std::io::Error> for crate::Error {
    fn from(e: std::io::Error) -> Self {
        crate::Error::StdIO(e)
    }
}

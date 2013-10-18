\name{passwords}
\alias{getPassword}
\alias{setPassword}
\alias{rmPassword}
\title{
  Functions to access password in user's keychain
}
\description{
  \code{getPassword} retireves a password stored in the keychain

  \code{setPassword} adds or modifies a password stored in the keychain

  \code{rmPassword} removes a password from the kaychain
}
\usage{
getPassword(service, user = NULL, quiet = FALSE, keychain = NULL)
setPassword(service, user = NULL, password, keychain = NULL)
 rmPassword(service, user = NULL, keychain = NULL)
}
%- maybe also 'usage' for other objects documented here.
\arguments{
  \item{service}{Name (arbitrary string) identifying the service}
  \item{user}{User name (if \code{NULL} the current login name of the
    user is used)}
  \item{quiet}{if \code{FALSE} then the function fails in case no
    password is found, if \code{TRUE} then \code{NULL} is returned
    in that case. Note that the function can still fail for other
    reasons (invalid parameters, keychain or denied access) regardless
    of the \code{quiet} flag.}
  \item{password}{new password (single string)}
  \item{keychain}{Keychain to operate on. If \code{NULL} then the
    default user keychain is used (recommended). In the current
    implementation that is the only valid value.}
}
\details{
  The above functions access and modify passwords in the current user's
  keychain. A keychain is a secure storage of information that can be
  locked and ulocked by the user. The functions above manipulate
  passwords associated with (service, user) pairs.

  The actual storage and method of determining user authorization is
  system-dependent. The current implementation uses the Security
  framework to work with users' keychain.
}
\value{
  \code{getPassword}: the currently stored password (decrypted) or
  \code{NULL} of \code{quiet=TRUE} and no password was found.

  \code{setPassword}: previous password or \code{NULL} if the password
  was just created.

  \code{rmPassword}: previous password
}
%\references{
%}
\author{
Simon Urbanek
}
\note{
  The current implementation uses default system keychain where
  supported. The system may ask the user for authentication to open the
  keychain.  

  The passwords are stored as generic passwords. Note that
  the actual service name used at the system level is prefixed with an
  R-specific prefix to prevent abuse by reading other passwords (such as
  your internet passwords etc.). However, malicious users could modify
  the package to allow arbitrary access, so be wary of the source from
  which you install this package.

  Please note that once you authorize R to access the keychain, it may
  be open for subsequent access.
}
\examples{
  pwd <- getPassword("foo", quiet=TRUE)
  if (is.null(pwd)) cat("foo doesn't exist yet\n")
  setPassword("foo",, "bar")
  pwd <- getPassword("foo")
  rmPassword("foo")
}
\keyword{utilities}

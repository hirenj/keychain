getPassword <- function(service, user=NULL, quiet=FALSE, keychain=NULL)
  .Call("find_password", service, user, NULL, quiet, FALSE)

setPassword <- function(service, user=NULL, password, keychain=NULL) {
  if (is.null(password)) stop("Invalid password")
  if (is.null(.Call("find_password", service, user, password, TRUE, FALSE)))
    .Call("store_password", service, user, password)
}

rmPassword <- function(service, user=NULL, keychain=NULL)
  .Call("find_password", service, user, NULL, FALSE, TRUE)

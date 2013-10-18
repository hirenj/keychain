#include <unistd.h>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__

#define SEC_PREFIX "R.keychain."

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

#include <Rinternals.h>

static char buf[1024];

static int chk_status(OSStatus status, const char *msg) {
    if (status != errSecSuccess) {
	CFStringRef rs = SecCopyErrorMessageString(status, 0);
	if (rs) {
	    if (CFStringGetCString(rs, buf, sizeof(buf), kCFStringEncodingUTF8)) {
		CFRelease(rs);
		Rf_error("Unable to %s password: %s", msg, buf);
	    }
	    CFRelease(rs);
	}
	Rf_error("Unable to %s password, system error code %d", msg, (int)status);
	return 1;
    }
    return 0;
}

SEXP store_password(SEXP svc, SEXP usr, SEXP pwd) {
    OSStatus status;
    SecKeychainRef kc = NULL; /* default */
    const char *un, *sn, *pw;
    char *svc_name;
    int l;

    if (TYPEOF(svc) != STRSXP || LENGTH(svc) != 1) Rf_error("Invalid service name");

    if (TYPEOF(pwd) != STRSXP || LENGTH(pwd) != 1) Rf_error("Invalid password");
    pw = Rf_translateCharUTF8(STRING_ELT(pwd, 0));

    if (usr == R_NilValue) {
	un = getlogin();
	if (!un) Rf_error("Unable to get current user name via getlogin()");
    } else {
	if (TYPEOF(usr) != STRSXP || LENGTH(usr) != 1)
	    Rf_error("Invalid user name (must be a character vector of length one)");
	un = Rf_translateCharUTF8(STRING_ELT(usr, 0));
    }
    
    sn = Rf_translateCharUTF8(STRING_ELT(svc, 0));
    l = strlen(sn);
    if (l > sizeof(buf) - 16) {
	svc_name = (char*) malloc(l + 16);
	if (!svc_name) Rf_error("Cannot allocate memory for service name");
    } else svc_name = buf;

    /* we are enforcing R.keychain. prefix to avoid abuse to access other system keys */
    strcpy(svc_name, SEC_PREFIX);
    strcat(svc_name, sn);

    status = SecKeychainAddGenericPassword(kc,
					   strlen(svc_name), svc_name,
					   strlen(un), un,
					   strlen(pw), pw,
					   NULL);
    if (svc_name != buf) free(svc_name);
    chk_status(status, "add");

    return R_NilValue;
}

SEXP find_password(SEXP svc, SEXP usr, SEXP new_pwd, SEXP quiet, SEXP del) {
    SEXP res;
    OSStatus status;
    SecKeychainRef kc = NULL; /* default */
    SecKeychainItemRef kci;
    const char *un, *sn;
    char *svc_name;
    void *pwd;
    UInt32 pwd_len = 0;
    int l;
    int silent = Rf_asInteger(quiet) == 1;
    int do_rm = Rf_asInteger(del) == 1;
    int modify = 0;

    if (TYPEOF(svc) != STRSXP || LENGTH(svc) != 1) Rf_error("Invalid service name");

    if (new_pwd != R_NilValue && (TYPEOF(new_pwd) != STRSXP || LENGTH(new_pwd) != 1))
	Rf_error("Invalid password");

    if (new_pwd != R_NilValue || do_rm) modify = 1;

    if (usr == R_NilValue) {
	un = getlogin();
	if (!un) Rf_error("Unable to get current user name via getlogin()");
    } else {
	if (TYPEOF(usr) != STRSXP || LENGTH(usr) != 1)
	    Rf_error("Invalid user name (must be a character vector of length one)");
	un = Rf_translateCharUTF8(STRING_ELT(usr, 0));
    }
    
    sn = Rf_translateCharUTF8(STRING_ELT(svc, 0));
    l = strlen(sn);
    if (l > sizeof(buf) - 16) {
	svc_name = (char*) malloc(l + 16);
	if (!svc_name) Rf_error("Cannot allocate memory for service name");
    } else svc_name = buf;

    /* we are enforcing R.keychain. prefix to avoid abuse to access other system keys */
    strcpy(svc_name, SEC_PREFIX);
    strcat(svc_name, sn);

    status = SecKeychainFindGenericPassword(kc,
					    strlen(svc_name), svc_name,
					    strlen(un), un,
					    &pwd_len, &pwd,
					    modify ? &kci : NULL);
    
    if (svc_name != buf) free(svc_name);
    if (silent && status == errSecItemNotFound) return R_NilValue;
    chk_status(status, "find");
        
    res = PROTECT(Rf_ScalarString(Rf_mkCharLenCE(pwd, pwd_len, CE_UTF8)));
    /* FIXME: we'll leak if the above fails in R */
    SecKeychainItemFreeContent(NULL, pwd);

    if (do_rm) {
	status = SecKeychainItemDelete(kci);
	chk_status(status, "delete");
    } else if (new_pwd != R_NilValue) { /* set a new one */
	const char *np = Rf_translateCharUTF8(STRING_ELT(new_pwd, 0));
	status = SecKeychainItemModifyContent(kci, NULL, strlen(np), np);
	chk_status(status, "modify");
    }

    UNPROTECT(1);
    return res;
}


#endif

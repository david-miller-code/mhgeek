#ifndef MHGEEK_XIAOMI_ACCOUNT_URL_H
#define MHGEEK_XIAOMI_ACCOUNT_URL_H

/* Matches the tracked trustedXiaomiURL redirect boundary: HTTPS, no userinfo
 * or fragment, case-insensitive account.xiaomi.com hostname, and no port or
 * port 443. Path and query may be empty. */
int mhg_xiaomi_account_redirect_is_trusted(const char *url);
/* Shared syntax primitive for typed redirect validators. Callers still own
 * their protocol-specific exact-host allowlist. */
int mhg_https_url_is_trusted_for_exact_host(const char *url,
                                            const char *hostname);

#endif

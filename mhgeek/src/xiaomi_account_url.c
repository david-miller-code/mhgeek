#include "xiaomi_account_url.h"

#include <stddef.h>
#include <string.h>

static int ascii_equal_fold(const char *left, const char *right, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        unsigned char a = (unsigned char)left[index];
        unsigned char b = (unsigned char)right[index];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
        if (a != b) return 0;
    }
    return 1;
}

int mhg_https_url_is_trusted_for_exact_host(const char *url,
                                            const char *hostname)
{
    static const char scheme[] = "https://";
    const char *authority;
    const char *authority_end;
    const char *colon;
    size_t hostname_len;

    if (!url || !hostname || !hostname[0] || strchr(hostname, ':') ||
        strchr(hostname, '/') ||
        strncmp(url, scheme, sizeof(scheme) - 1u) != 0 ||
        strchr(url, '#'))
        return 0;
    authority = url + sizeof(scheme) - 1u;
    authority_end = authority + strcspn(authority, "/?");
    if (authority_end == authority || memchr(authority, '@',
                                              (size_t)(authority_end - authority)))
        return 0;
    colon = memchr(authority, ':', (size_t)(authority_end - authority));
    hostname_len = colon ? (size_t)(colon - authority) :
                           (size_t)(authority_end - authority);
    if (hostname_len != strlen(hostname) ||
        !ascii_equal_fold(authority, hostname, hostname_len))
        return 0;
    if (colon && ((size_t)(authority_end - colon) != sizeof(":443") - 1u ||
                  memcmp(colon, ":443", sizeof(":443") - 1u) != 0))
        return 0;
    return 1;
}

int mhg_xiaomi_account_redirect_is_trusted(const char *url)
{
    return mhg_https_url_is_trusted_for_exact_host(
        url, "account.xiaomi.com");
}

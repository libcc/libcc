#include <libcc/http.h>

/*
 * Official static header table for HPACK
*   +-------+-----------------------------+---------------+
	| 1     | :authority                  |               |
	| 2     | :method                     | GET           |
	| 3     | :method                     | POST          |
	| 4     | :path                       | /             |
	| 5     | :path                       | /index.html   |
	| 6     | :scheme                     | http          |
	| 7     | :scheme                     | https         |
	| 8     | :status                     | 200           |
	| 9     | :status                     | 204           |
	| 10    | :status                     | 206           |
	| 11    | :status                     | 304           |
	| 12    | :status                     | 400           |
	| 13    | :status                     | 404           |
	| 14    | :status                     | 500           |
	| 15    | accept-charset              |               |
	| 16    | accept-encoding             | gzip, deflate |
	| 17    | accept-language             |               |
	| 18    | accept-ranges               |               |
	| 19    | accept                      |               |
	| 20    | access-control-allow-origin |               |
	| 21    | age                         |               |
	| 22    | allow                       |               |
	| 23    | authorization               |               |
	| 24    | cache-control               |               |
	| 25    | content-disposition         |               |
	| 26    | content-encoding            |               |
	| 27    | content-language            |               |
	| 28    | content-length              |               |
	| 29    | content-location            |               |
	| 30    | content-range               |               |
	| 31    | content-type                |               |
	| 32    | cookie                      |               |
	| 33    | date                        |               |
	| 34    | etag                        |               |
	| 35    | expect                      |               |
	| 36    | expires                     |               |
	| 37    | from                        |               |
	| 38    | host                        |               |
	| 39    | if-match                    |               |
	| 40    | if-modified-since           |               |
	| 41    | if-none-match               |               |
	| 42    | if-range                    |               |
	| 43    | if-unmodified-since         |               |
	| 44    | last-modified               |               |
	| 45    | link                        |               |
	| 46    | location                    |               |
	| 47    | max-forwards                |               |
	| 48    | proxy-authenticate          |               |
	| 49    | proxy-authorization         |               |
	| 50    | range                       |               |
	| 51    | referer                     |               |
	| 52    | refresh                     |               |
	| 53    | retry-after                 |               |
	| 54    | server                      |               |
	| 55    | set-cookie                  |               |
	| 56    | strict-transport-security   |               |
	| 57    | transfer-encoding           |               |
	| 58    | user-agent                  |               |
	| 59    | vary                        |               |
	| 60    | via                         |               |
	| 61    | www-authenticate            |               |
	+-------+-----------------------------+---------------+
*/

static const uint8_t static_hdr_len[62] = {
	0, /* starts at 1 */
	10,  7,  7,  5,  5,    7,  7,  7,  7,  7,
	7,  7,  7,  7, 14,   15, 15, 13,  6, 27,
	3,  5, 13, 13, 19,   16, 16, 14, 16, 13,
	12,  6,  4,  4,  6,    7,  4,  4,  8, 17,
	13,  8, 19, 13,  4,    8, 12, 18, 19,  5,
	7,  7, 11,  6, 10,   25, 17, 10,  4,  3,
	16
};

static const unsigned char static_token[] = {
	0,
	_CC_TOKEN_HTTP_COLON_AUTHORITY_,
	_CC_TOKEN_HTTP_COLON_METHOD_,
	_CC_TOKEN_HTTP_COLON_METHOD_,
	_CC_TOKEN_HTTP_COLON_PATH_,
	_CC_TOKEN_HTTP_COLON_PATH_,
	_CC_TOKEN_HTTP_COLON_SCHEME_,
	_CC_TOKEN_HTTP_COLON_SCHEME_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_COLON_STATUS_,
	_CC_TOKEN_HTTP_ACCEPT_CHARSET_,
	_CC_TOKEN_HTTP_ACCEPT_ENCODING_,
	_CC_TOKEN_HTTP_ACCEPT_LANGUAGE_,
	_CC_TOKEN_HTTP_ACCEPT_RANGES_,
	_CC_TOKEN_HTTP_ACCEPT_,
	_CC_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN_,
	_CC_TOKEN_HTTP_AGE_,
	_CC_TOKEN_HTTP_ALLOW_,
	_CC_TOKEN_HTTP_AUTHORIZATION_,
	_CC_TOKEN_HTTP_CACHE_CONTROL_,
	_CC_TOKEN_HTTP_CONTENT_DISPOSITION_,
	_CC_TOKEN_HTTP_CONTENT_ENCODING_,
	_CC_TOKEN_HTTP_CONTENT_LANGUAGE_,
	_CC_TOKEN_HTTP_CONTENT_LENGTH_,
	_CC_TOKEN_HTTP_CONTENT_LOCATION_,
	_CC_TOKEN_HTTP_CONTENT_RANGE_,
	_CC_TOKEN_HTTP_CONTENT_TYPE_,
	_CC_TOKEN_HTTP_COOKIE_,
	_CC_TOKEN_HTTP_DATE_,
	_CC_TOKEN_HTTP_ETAG_,
	_CC_TOKEN_HTTP_EXPECT_,
	_CC_TOKEN_HTTP_EXPIRES_,
	_CC_TOKEN_HTTP_FROM_,
	_CC_TOKEN_HOST_,
	_CC_TOKEN_HTTP_IF_MATCH_,
	_CC_TOKEN_HTTP_IF_MODIFIED_SINCE_,
	_CC_TOKEN_HTTP_IF_NONE_MATCH_,
	_CC_TOKEN_HTTP_IF_RANGE_,
	_CC_TOKEN_HTTP_IF_UNMODIFIED_SINCE_,
	_CC_TOKEN_HTTP_LAST_MODIFIED_,
	_CC_TOKEN_HTTP_LINK_,
	_CC_TOKEN_HTTP_LOCATION_,
	_CC_TOKEN_HTTP_MAX_FORWARDS_,
	_CC_TOKEN_HTTP_PROXY_AUTHENTICATE_,
	_CC_TOKEN_HTTP_PROXY_AUTHORIZATION_,
	_CC_TOKEN_HTTP_RANGE_,
	_CC_TOKEN_HTTP_REFERER_,
	_CC_TOKEN_HTTP_REFRESH_,
	_CC_TOKEN_HTTP_RETRY_AFTER_,
	_CC_TOKEN_HTTP_SERVER_,
	_CC_TOKEN_HTTP_SET_COOKIE_,
	_CC_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY_,
	_CC_TOKEN_HTTP_TRANSFER_ENCODING_,
	_CC_TOKEN_HTTP_USER_AGENT_,
	_CC_TOKEN_HTTP_VARY_,
	_CC_TOKEN_HTTP_VIA_,
	_CC_TOKEN_HTTP_WWW_AUTHENTICATE_,
};

/* some of the entries imply values as well as header names */
static const char * const http2_canned[] = {
	"",
	"",
	"GET",
	"POST",
	"/",
	"/index.html",
	"http",
	"https",
	"200",
	"204",
	"206",
	"304",
	"400",
	"404",
	"500",
	"",
	"gzip, deflate"
};
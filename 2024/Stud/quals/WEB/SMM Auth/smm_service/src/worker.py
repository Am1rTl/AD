from .config import get_settings
from urllib.parse import urlparse, parse_qs

settings = get_settings()


def get_auth_url():
    return f"{settings.oauth2_service_authorization_endpoint}?client_id={settings.client_id}&redirect_uri={settings.smm_service_redirect_uri}&response_type=code&scope=profile"


def get_token_request(code: str):
    data = {
        "client_id": settings.client_id,
        "client_secret": settings.client_secret_key,
        "grant_type": settings.grant_type,
        "code": code,
        "redirect_uri": settings.smm_service_redirect_uri,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    return data, headers


def compares_urls(urls: list[str]):
    parsed_standard_url = urlparse(get_auth_url())
    standard_queries = parse_qs(parsed_standard_url.query)

    for url in urls:
        flag = False
        parsed_url = urlparse(url.strip())
        if (
            parsed_standard_url.scheme == parsed_url.scheme
            and parsed_standard_url.netloc == parsed_url.netloc
            and parsed_standard_url.path == parsed_url.path
        ):
            url_queries = parse_qs(parsed_url.query)
            for parameter_key, parameter_value in standard_queries.items():
                if parameter_key in url_queries:
                    if (
                        parameter_key != "redirect_uri"
                        and parameter_value[0] != url_queries[parameter_key][-1]
                    ):
                        flag = False
                        break
                    flag = True
                else:
                    flag = False
                    break

        if flag:
            return url_queries["redirect_uri"][-1]

    return None

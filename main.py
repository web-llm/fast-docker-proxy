import os

import dotenv
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from urllib.parse import urlencode, urljoin
from contextlib import asynccontextmanager
from starlette.background import BackgroundTask
import uvicorn

dotenv.load_dotenv()

CUSTOM_DOMAIN = os.getenv("CUSTOM_DOMAIN", "example.com")
MODE = os.getenv("MODE", "prod")
TARGET_UPSTREAM = os.getenv("TARGET_UPSTREAM", "https://registry-1.docker.io")

dockerHub = "https://registry-1.docker.io"

routes = {
    f"docker.{CUSTOM_DOMAIN}": dockerHub,
    f"quay.{CUSTOM_DOMAIN}": "https://quay.io",
    f"gcr.{CUSTOM_DOMAIN}": "https://gcr.io",
    f"k8s-gcr.{CUSTOM_DOMAIN}": "https://k8s.gcr.io",
    f"k8s.{CUSTOM_DOMAIN}": "https://registry.k8s.io",
    f"ghcr.{CUSTOM_DOMAIN}": "https://ghcr.io",
    f"cloudsmith.{CUSTOM_DOMAIN}": "https://docker.cloudsmith.io",
    f"ecr.{CUSTOM_DOMAIN}": "https://public.ecr.aws",
    f"docker-staging.{CUSTOM_DOMAIN}": dockerHub,
}


def route_by_host(host: str) -> str:
    """Return the upstream registry for a given hostname."""
    host = host.split(":", 1)[0]
    if host in routes:
        return routes[host]
    if MODE == "debug":
        return TARGET_UPSTREAM
    return ""


# -----------------------------
# Global HTTP client & lifespan
# -----------------------------

client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for FastAPI.
    Initializes a global reusable HTTP client and closes it on shutdown.
    """
    global client
    client = httpx.AsyncClient(timeout=30.0)
    try:
        yield
    finally:
        await client.aclose()


app = FastAPI(lifespan=lifespan)


async def fetch_with_client(
    url: str,
    method: str = "GET",
    headers: list[tuple[str, str]] | dict | None = None,
    follow_redirects: bool = True,
) -> httpx.Response:
    """Wrapper around the global HTTP client."""
    assert client is not None, "HTTP client not initialized"
    return await client.request(
        method,
        url,
        headers=headers,
        follow_redirects=follow_redirects,
    )


def parse_www_authenticate(auth_header: str):
    """
    Parse the WWW-Authenticate header for Bearer auth.
    Example: Bearer realm="https://auth.docker.com/token",service="registry.docker.io"
    """
    parts = auth_header.split('"')
    realm = parts[1]
    service = parts[3]
    return realm, service


def append_query_params(url: str, params: list[tuple[str, str]]) -> str:
    """Append query parameters while preserving any existing upstream query."""
    if not params:
        return url

    separator = "&" if "?" in url else "?"
    return url + separator + urlencode(params)


async def fetch_token(realm, service, scope, authorization):
    """Request a token from the registry authentication server."""
    params = {}
    if service:
        params["service"] = service
    if scope:
        params["scope"] = scope

    url = append_query_params(realm, list(params.items()))
    headers = {}
    if authorization:
        headers["Authorization"] = authorization

    return await fetch_with_client(url, headers=headers)


def response_unauthorized(host: str):
    """Return a 401 response with a proper WWW-Authenticate header."""
    scheme = "http" if MODE == "debug" else "https"
    www_auth = (
        f'Bearer realm="{scheme}://{host}/v2/auth",service="cloudflare-docker-proxy"'
    )

    return JSONResponse(
        status_code=401,
        content={"message": "UNAUTHORIZED"},
        headers={"WWW-Authenticate": www_auth},
    )


# -----------------------------
# Main Proxy Logic (streaming)
# -----------------------------


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy(full_path: str, request: Request):
    """
    Main reverse-proxy entrypoint.
    Routes registry API requests to the configured upstream registry,
    with correct authentication handling and streaming of large blobs.
    """

    # 1. Determine upstream registry
    host = request.headers.get("host", "")
    upstream = route_by_host(host)

    if upstream == "":
        return JSONResponse(status_code=404, content={"routes": list(routes.keys())})

    is_dockerhub = upstream == dockerHub

    # Reconstruct full URL path
    original_url = request.url
    path = "/" + full_path

    # 2. Redirect "/" → "/v2/"
    if path == "/":
        return RedirectResponse(
            url=f"{original_url.scheme}://{host}/v2/", status_code=301
        )

    # 3. Handle /v2/ (small response, no streaming needed)
    if path == "/v2/":
        upstream_url = urljoin(upstream, "/v2/")
        headers: list[tuple[str, str]] = []
        auth = request.headers.get("Authorization")
        if auth:
            headers.append(("Authorization", auth))

        resp = await fetch_with_client(upstream_url, headers=headers)

        if resp.status_code == 401:
            return response_unauthorized(host)

        return Response(
            content=resp.content, status_code=resp.status_code, headers=resp.headers
        )

    # 4. Handle /v2/auth (token responses are small)
    if path == "/v2/auth":
        probe_url = urljoin(upstream, "/v2/")
        probe_resp = await fetch_with_client(probe_url)

        if probe_resp.status_code != 401:
            return Response(probe_resp.content, status_code=probe_resp.status_code)

        auth_header = probe_resp.headers.get("WWW-Authenticate")
        if auth_header is None:
            return Response(probe_resp.content, status_code=probe_resp.status_code)

        realm, service = parse_www_authenticate(auth_header)

        # Autocomplete repository scope for DockerHub library images
        scope = dict(request.query_params).get("scope")
        if scope and is_dockerhub:
            parts = scope.split(":")
            if len(parts) == 3 and "/" not in parts[1]:
                parts[1] = "library/" + parts[1]
                scope = ":".join(parts)

        authorization = request.headers.get("Authorization")

        token_resp = await fetch_token(realm, service, scope, authorization)
        return Response(
            content=token_resp.content,
            status_code=token_resp.status_code,
            headers=token_resp.headers,
        )

    # 5. DockerHub library auto-prefix
    if is_dockerhub:
        parts = path.split("/")
        # Example: /v2/busybox/manifests/latest → /v2/library/busybox/manifests/latest
        if len(parts) == 5:
            parts.insert(2, "library")
            new_path = "/".join(parts)
            new_url = f"{original_url.scheme}://{host}{new_path}"
            return RedirectResponse(url=new_url, status_code=301)

    # 6. Proxy all other requests (streaming mode to reduce memory usage)
    upstream_url = append_query_params(upstream + path, list(request.query_params.multi_items()))

    # Hop-by-hop headers must not be forwarded
    hop_by_hop = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
    }

    forward_headers: list[tuple[str, str]] = []
    for raw_key, raw_value in request.headers.raw:
        key = raw_key.decode("latin-1")
        if key.lower() in hop_by_hop:
            continue
        forward_headers.append((key, raw_value.decode("latin-1")))

    # DockerHub blob requests return 307 and must be followed manually
    follow = False if is_dockerhub else True

    assert client is not None, "HTTP client not initialized"

    # Build and send a streaming request without using an async context manager,
    # so that we can keep the stream open until the response is fully consumed.
    body = None
    if request.method not in {"GET", "HEAD"}:
        body = await request.body()

    req = client.build_request(
        request.method,
        upstream_url,
        headers=forward_headers,
        content=body,
    )
    upstream_resp = await client.send(
        req,
        stream=True,
        follow_redirects=follow,
    )

    status_code = upstream_resp.status_code
    response_headers = dict(upstream_resp.headers)

    print(
        f"Proxying: {upstream_url}, headers: {forward_headers}, status: {status_code}"
    )

    # 6A. Unauthorized
    if status_code == 401:
        # Close upstream response before returning
        await upstream_resp.aclose()
        return response_unauthorized(host)

    # 6B. DockerHub requires manual handling of 307 blob redirects
    if is_dockerhub and status_code == 307:
        location = upstream_resp.headers.get("Location")
        if not location:
            # No Location header—return 307 as-is but with an empty body
            await upstream_resp.aclose()

            async def iter_empty():
                if False:
                    yield b""

            return StreamingResponse(
                iter_empty(),
                status_code=status_code,
                headers=response_headers,
            )

        # Close the initial 307 response before following the redirect
        await upstream_resp.aclose()

        # Manually stream the redirected blob
        blob_req = client.build_request("GET", location)
        blob_resp = await client.send(
            blob_req,
            stream=True,
            follow_redirects=True,
        )
        blob_headers = dict(blob_resp.headers)

        # Remove hop-by-hop headers
        for h in hop_by_hop:
            blob_headers.pop(h, None)

        # Use a background task to close blob_resp once streaming is done
        background = BackgroundTask(blob_resp.aclose)

        return StreamingResponse(
            blob_resp.aiter_bytes(),
            status_code=blob_resp.status_code,
            headers=blob_headers,
            background=background,
        )

    # Regular streaming proxy response
    for h in hop_by_hop:
        response_headers.pop(h, None)

    # Use a background task to close upstream_resp when done streaming
    background = BackgroundTask(upstream_resp.aclose)

    return StreamingResponse(
        upstream_resp.aiter_bytes(),
        status_code=status_code,
        headers=response_headers,
        background=background,
    )


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000, log_level="debug")

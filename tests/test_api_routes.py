from fastapi import Response

from app.main import app


def test_no_content_routes_use_empty_response_class():
    routes = {
        route.path: route
        for route in app.routes
        if getattr(route, "status_code", None) == 204
    }

    assert routes["/api/custom-advisories/{advisory_id}"].response_class is Response
    assert routes["/api/scans/{scan_id}"].response_class is Response

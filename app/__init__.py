import uuid
import logging
from flask import Flask, request, jsonify, g

from app.config import (
    BASE_DIR,
    MAX_UPLOAD_SIZE_BYTES
)
from app.models import init_db
from app.seed_data import seed_database_and_storage
from app.proxy_layer import ProxyLayer
from app.firewall_layer import FirewallLayer
from app.routes.auth_routes import auth_bp
from app.routes.file_routes import file_bp
from app.routes.soc_routes import soc_bp
from app.routes.client_routes import client_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
)
logger = logging.getLogger("secure_file_system")

def create_app() -> Flask:
    """Application factory assembling defense-in-depth security pipeline."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static")
    )

    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE_BYTES

    # Initialize Database Schema & Seed Data
    init_db()
    seed_database_and_storage()

    # =========================================================================
    # DEFENSE-IN-DEPTH MIDDLEWARE PIPELINE
    # Order: [1. Proxy Layer] -> [2. Firewall Layer]
    # =========================================================================

    @app.before_request
    def defense_in_depth_pipeline():
        # Assign unique tracing ID for distributed audit tracking
        g.request_id = request.headers.get("X-Request-ID") or f"REQ-{uuid.uuid4().hex[:12].upper()}"

        # Skip static assets from strict middleware if any
        if request.path.startswith("/static/"):
            return None

        # ---------------------------------------------------------------------
        # LAYER 1: Proxy Layer (Protocol, Method & Header Inspection)
        # ---------------------------------------------------------------------
        proxy_violation = ProxyLayer.inspect_request(request, g.request_id)
        if proxy_violation:
            return proxy_violation

        # ---------------------------------------------------------------------
        # LAYER 2: Firewall Layer (IP Filter, Rate Limit, Payload Size)
        # ---------------------------------------------------------------------
        # We don't block the static UI index page so user can see the block notice
        if request.path != "/" and not request.path.startswith("/static/"):
            firewall_violation = FirewallLayer.inspect_packet(request, g.request_id)
            if firewall_violation:
                err_dict, code = firewall_violation
                return jsonify(err_dict), code

        return None

    @app.after_request
    def security_headers_and_tracing(response):
        """Append zero-trust security headers and correlation ID to all outgoing responses."""
        request_id = getattr(g, "request_id", "NO-REQ-ID")
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Server"] = "SecureGateway-ReverseProxy/2.6"
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-Request-ID, X-Upload-Path, X-Upload-Filename"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    # Global Error Handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "error": "Not Found",
            "message": "The requested API endpoint or resource does not exist.",
            "request_id": getattr(g, "request_id", "NO-REQ-ID")
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({
            "error": "Method Not Allowed",
            "message": "The HTTP method is not permitted on this resource.",
            "request_id": getattr(g, "request_id", "NO-REQ-ID")
        }), 405

    @app.errorhandler(413)
    def payload_too_large(e):
        return jsonify({
            "error": "Payload Too Large",
            "message": "Upload size exceeds system firewall threshold.",
            "request_id": getattr(g, "request_id", "NO-REQ-ID")
        }), 413

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Internal Server Error: {e}", exc_info=True)
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred. Incident logged.",
            "request_id": getattr(g, "request_id", "NO-REQ-ID")
        }), 500

    # Register Blueprints
    app.register_blueprint(client_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(soc_bp)

    return app

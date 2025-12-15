from auth import token_required
from database import execute_query
from flask import Blueprint, jsonify, request
from werkzeug import secure_filename
import random
import os
from config import SECURE_MODE
import requests
from urllib import urlparse

profile_pic_bp = Blueprint("upload_profile_picture", __name__, "./static")



@profile_pic_bp.route("/upload_profile_picture", methods=["POST"])
@token_required
def upload_profile_picture(current_user):

    def _unsecure_upload_profile_picture_route():
        if "profile_picture" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["profile_picture"]

        if file.filename == "":
            return jsonify({"error": "No file selected"}), 400

        try:
            # Vulnerability: No file type validation
            # Vulnerability: Using user-controlled filename
            # Vulnerability: No file size check
            # Vulnerability: No content-type validation
            filename = secure_filename(file.filename)

            # Add random prefix to prevent filename collisions
            filename = f"{random.randint(1, 1000000)}_{filename}"

            # Vulnerability: Path traversal possible if filename contains ../
            file_path = os.path.join(UPLOAD_FOLDER, filename)

            file.save(file_path)

            # Update database with just the filename
            execute_query(
                "UPDATE users SET profile_picture = %s WHERE id = %s",
                (filename, current_user["user_id"]),
                fetch=False,
            )

            return jsonify(
                {
                    "status": "success",
                    "message": "Profile picture uploaded successfully",
                    "file_path": os.path.join(
                        "static/uploads", filename
                    ),  # Vulnerability: Path disclosure
                }
            )

        except Exception as e:
            # Vulnerability: Detailed error exposure
            print(f"Profile picture upload error: {str(e)}")
            return jsonify(
                {
                    "status": "error",
                    "message": str(e),
                    "file_path": file_path,  # Vulnerability: Information disclosure
                }
            ), 500

    def _secure_upload_profile_picture_route():
        raise NotImplementedError("fix is not yet implemented")


    if SECURE_MODE:
        return _secure_upload_profile_picture_route()
    else:
        return _unsecure_upload_profile_picture_route()






# Upload profile picture by URL (Intentionally Vulnerable to SSRF)
@profile_pic_bp.route("/upload_profile_picture_url", methods=["POST"])
@token_required
def upload_profile_picture_url(current_user):

    def _unsecure_upload_profile_picture_url():
        try:
            data = request.get_json() or {}
            image_url = data.get("image_url")

            if not image_url:
                return jsonify(
                    {"status": "error", "message": "image_url is required"}
                ), 400

            # Vulnerabilities:
            # - No URL scheme/host allowlist (SSRF)
            # - SSL verification disabled
            # - Follows redirects
            # - No content-type or size validation
            resp = requests.get(
                image_url, timeout=10, allow_redirects=True, verify=False
            )
            if resp.status_code >= 400:
                return jsonify(
                    {
                        "status": "error",
                        "message": f"Failed to fetch URL: HTTP {resp.status_code}",
                    }
                ), 400

            # Derive filename from URL path (user-controlled)
            parsed = urlparse(image_url)
            basename = os.path.basename(parsed.path) or "downloaded"
            filename = secure_filename(basename)
            filename = f"{random.randint(1, 1000000)}_{filename}"
            file_path = os.path.join(UPLOAD_FOLDER, filename)

            # Save content directly without validation
            with open(file_path, "wb") as f:
                f.write(resp.content)

            # Store just the filename in DB (same pattern as file upload)
            execute_query(
                "UPDATE users SET profile_picture = %s WHERE id = %s",
                (filename, current_user["user_id"]),
                fetch=False,
            )

            return jsonify(
                {
                    "status": "success",
                    "message": "Profile picture imported from URL",
                    "file_path": os.path.join("static/uploads", filename),
                    "debug_info": {  # Information disclosure for learning
                        "fetched_url": image_url,
                        "http_status": resp.status_code,
                        "content_length": len(resp.content),
                    },
                }
            )
        except Exception as e:
            print(f"URL image import error: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    def _secure_upload_pofile_picture_url():
        raise NotImplementedError()


    if SECURE_MODE:
        return _secure_upload_pofile_picture_url()
    else:
        return _unsecure_upload_profile_picture_url()


from flask import Blueprint

from . import chat

ai_blueprint = Blueprint("ai", __name__, './static')
ai_blueprint.register_blueprint(chat.bp)
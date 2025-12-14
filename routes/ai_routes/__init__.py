from flask import Blueprint

from . import chat, chat_anonymous

ai_blueprint = Blueprint("ai", __name__, './static')
ai_blueprint.register_blueprint(chat.bp)
ai_blueprint.register_blueprint(chat_anonymous.bp)

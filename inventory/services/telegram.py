"""
Telegram notification service. Sends to all enabled Telegram integrations.
"""
import html
import re
import logging
import requests
from inventory.config_manager import get_telegram_integrations
from typing import Optional

logger = logging.getLogger(__name__)


def escape_telegram_html(s: str) -> str:
    """Escape string for use inside Telegram HTML (e.g. inside <code> or <b>). Use for dynamic content."""
    if not s:
        return s
    return html.escape(str(s), quote=True)


def _send_one(
    token: str,
    chat_id: str,
    text: str,
    parse_mode: str = 'HTML',
    reply_markup: Optional[dict] = None,
) -> bool:
    """Send message to one Telegram (token, chat_id). Returns True on success."""
    if not token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode}
    if reply_markup:
        payload['reply_markup'] = reply_markup
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 400 and parse_mode:
            plain = re.sub(r'</?[a-z]+>', '', text)
            plain = plain.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
            try:
                r2 = requests.post(url, json={'chat_id': chat_id, 'text': plain}, timeout=10)
                r2.raise_for_status()
                return True
            except requests.exceptions.RequestException:
                return False
        return False
    except requests.exceptions.RequestException:
        return False


def send_telegram(
    text: str,
    parse_mode: str = 'HTML',
    reply_markup: Optional[dict] = None,
) -> bool:
    """
    Send a message to all enabled Telegram integrations.

    Args:
        text: Message text (may contain HTML tags like <b>, <code>).
        parse_mode: Parse mode (HTML or Markdown).
        reply_markup: Optional InlineKeyboardMarkup dict, e.g. {"inline_keyboard": [[{"text": "Btn", "callback_data": "data"}]]}.

    Returns:
        True if sent to at least one integration successfully, False otherwise
    """
    integrations = get_telegram_integrations()
    if not integrations:
        logger.warning(
            "Telegram not configured: no enabled integration with bot_token and chat_id. "
            "Add one in Settings > Integrations."
        )
        return False
    any_ok = False
    for integration in integrations:
        token = integration.get_config('bot_token', '')
        chat_id = integration.get_config('chat_id', '')
        if _send_one(token, chat_id, text, parse_mode, reply_markup):
            any_ok = True
            logger.info("Telegram notification sent to %s", integration.display_name or integration.get_name_display())
        else:
            logger.warning("Failed to send Telegram to %s", integration.display_name or integration.get_name_display())
    return any_ok


def send_telegram_to_integration(
    integration,
    text: str,
    parse_mode: str = 'HTML',
    reply_markup: Optional[dict] = None,
) -> bool:
    """
    Send a message to a specific Telegram integration (e.g. to reply to a bot command).

    Args:
        integration: IntegrationConfig instance (telegram type).
        text: Message text (may contain HTML).
        parse_mode: Parse mode (HTML or Markdown).
        reply_markup: Optional InlineKeyboardMarkup dict.

    Returns:
        True if sent successfully.
    """
    token = integration.get_config('bot_token', '')
    chat_id = integration.get_config('chat_id', '')
    return _send_one(token, chat_id, text, parse_mode, reply_markup)


def inline_keyboard_setname(ip: str) -> dict:
    """Build InlineKeyboardMarkup with one button 'Asignar nombre' for the given IP."""
    return {
        'inline_keyboard': [
            [{'text': '✏️ Asignar nombre', 'callback_data': f'setname:{ip}'}],
            [{'text': '📖 Ver comandos', 'callback_data': 'help'}],
        ]
    }


def answer_callback_query(token: str, callback_query_id: str, text: str = None) -> bool:
    """Answer a callback query (e.g. after user tapped an inline button)."""
    if not token or not callback_query_id:
        return False
    url = f"https://api.telegram.org/bot{token}/answerCallbackQuery"
    payload = {'callback_query_id': callback_query_id}
    if text:
        payload['text'] = text[:200]
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException:
        return False

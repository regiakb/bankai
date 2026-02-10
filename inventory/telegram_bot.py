"""
Telegram bot command handlers. Used by webhook or long-polling (run_telegram_bot).
Handles /start, /help, /setname, /scan.
"""
import logging
import re
import threading
from django.core.management import call_command
from django.utils import timezone

from inventory.models import Host, IPAddress, HostSource
from inventory.config_manager import get_discovery_cidr
from inventory.services.telegram import (
    send_telegram_to_integration,
    escape_telegram_html,
    answer_callback_query,
)

logger = logging.getLogger(__name__)


def handle_update(integration, update: dict) -> bool:
    """
    Process a Telegram update (message or callback_query). Only responds if from configured chat_id.
    Returns True if the update was handled.
    """
    # Handle inline button taps (callback_query)
    callback = update.get('callback_query')
    if callback:
        return _handle_callback_query(integration, callback)

    message = update.get('message') or update.get('edited_message')
    if not message:
        return False

    chat_id = str(message.get('chat', {}).get('id', ''))
    configured_chat = integration.get_config('chat_id', '').strip()
    if configured_chat and chat_id != configured_chat:
        logger.warning("Telegram message from unknown chat_id %s, ignoring", chat_id)
        return True  # Still "handled" to avoid retries

    text = (message.get('text') or '').strip()
    if not text:
        return False

    # Command routing
    if text.startswith('/start'):
        send_telegram_to_integration(
            integration,
            "🤖 <b>BANKAI Bot</b>\n\n"
            "Commands:\n"
            "• /help — Show this help\n"
            "• /setname &lt;IP&gt; &lt;name&gt; — Set host name for an IP\n"
            "• /scan discovery [CIDR] — Run discovery scan (default: configured CIDR)\n"
            "• /scan services [targets] — Run service scan (default: from_db)\n\n"
            "After a scan, use /setname to assign a name to a host."
        )
        return True
    if text.startswith('/help'):
        send_telegram_to_integration(
            integration,
            "📖 <b>Commands</b>\n\n"
            "<b>/setname</b> <code>IP name</code>\n"
            "Assign a friendly name to a host by IP.\n"
            "Example: /setname 192.168.1.10 My Server\n\n"
            "<b>/scan discovery</b> [CIDR]\n"
            "Run network discovery. Optional: CIDR (e.g. 192.168.1.0/24).\n\n"
            "<b>/scan services</b> [targets]\n"
            "Run service scan. Optional: targets (e.g. from_db or 192.168.1.0/24).\n\n"
            "Scan results will be sent here; then use /setname to name hosts."
        )
        return True
    if text.startswith('/setname'):
        return _handle_setname(integration, text)
    if text.startswith('/scan'):
        return _handle_scan(integration, chat_id, text)

    send_telegram_to_integration(
        integration,
        "Unknown command. Send /help for available commands."
    )
    return True


def _handle_callback_query(integration, callback: dict) -> bool:
    """Handle inline keyboard button tap (callback_query)."""
    chat_id = str(callback.get('message', {}).get('chat', {}).get('id', ''))
    configured_chat = integration.get_config('chat_id', '').strip()
    if configured_chat and chat_id != configured_chat:
        return True
    data = (callback.get('data') or '').strip()
    callback_id = callback.get('id')
    token = integration.get_config('bot_token', '')

    if data == 'help':
        answer_callback_query(token, callback_id)
        send_telegram_to_integration(
            integration,
            "📖 <b>Commands</b>\n\n"
            "<b>/setname</b> <code>IP name</code> — Set host name\n"
            "E.g.: /setname 192.168.1.10 My Server\n\n"
            "<b>/scan discovery</b> [CIDR] — Run discovery scan\n\n"
            "<b>/scan services</b> [targets] — Run service scan\n\n"
            "Notifications include buttons to set host name."
        )
        return True
    if data.startswith('setname:'):
        ip = data[7:].strip()
        answer_callback_query(token, callback_id, "Send name with /setname")
        send_telegram_to_integration(
            integration,
            f"✏️ To set name for <code>{escape_telegram_html(ip)}</code> send:\n\n"
            f"<code>/setname {escape_telegram_html(ip)} HostName</code>\n\n"
            "Example: /setname " + escape_telegram_html(ip) + " My Server"
        )
        return True
    answer_callback_query(token, callback_id)
    return True


def _handle_setname(integration, text: str) -> bool:
    # /setname 192.168.1.10 My Server
    parts = text.split(maxsplit=2)
    if len(parts) < 3:
        send_telegram_to_integration(
            integration,
            "Usage: /setname &lt;IP&gt; &lt;name&gt;\nExample: /setname 192.168.1.10 My Server"
        )
        return True

    ip = parts[1].strip()
    name = parts[2].strip()
    if not name:
        send_telegram_to_integration(integration, "Name cannot be empty.")
        return True

    ip_obj = IPAddress.objects.filter(ip=ip).first()
    if not ip_obj:
        send_telegram_to_integration(
            integration,
            f"IP <code>{escape_telegram_html(ip)}</code> not in inventory. Run a discovery scan first."
        )
        return True

    host = ip_obj.host
    if not host:
        host = Host.objects.create(
            name=name,
            source=HostSource.MANUAL,
        )
        ip_obj.host = host
        ip_obj.save()
    else:
        host.name = name
        host.save()

    send_telegram_to_integration(
        integration,
        f"✅ Host name set: <code>{escape_telegram_html(ip)}</code> → <b>{escape_telegram_html(name)}</b>"
    )
    return True


def _handle_scan(integration, chat_id: str, text: str) -> bool:
    # /scan discovery [cidr]   or   /scan services [targets]
    parts = text.split(maxsplit=2)
    if len(parts) < 2:
        send_telegram_to_integration(
            integration,
            "Usage: /scan discovery [CIDR] or /scan services [targets]"
        )
        return True

    scan_type = parts[1].lower()
    extra = (parts[2].strip() if len(parts) > 2 else '').strip()

    if scan_type == 'discovery':
        cidr = extra or get_discovery_cidr()
        send_telegram_to_integration(
            integration,
            f"🔄 Starting discovery scan for <code>{escape_telegram_html(cidr)}</code>. I'll send results when done."
        )
        threading.Thread(
            target=_run_scan_and_notify,
            args=(integration.pk, 'scan_discovery', {'cidr': cidr}),
            daemon=True
        ).start()
        return True
    if scan_type == 'services':
        targets = extra or 'from_db'
        send_telegram_to_integration(
            integration,
            f"🔄 Starting service scan (targets: <code>{escape_telegram_html(targets)}</code>). I'll send results when done."
        )
        threading.Thread(
            target=_run_scan_and_notify,
            args=(integration.pk, 'scan_services', {'targets': targets}),
            daemon=True
        ).start()
        return True

    send_telegram_to_integration(
        integration,
        "Unknown scan type. Use: /scan discovery [CIDR] or /scan services [targets]"
    )
    return True


def _run_scan_and_notify(integration_id: int, command_name: str, options: dict):
    """Run a management command and send a summary to the integration's chat."""
    from inventory.models import IntegrationConfig

    integration = IntegrationConfig.objects.filter(pk=integration_id, name='telegram').first()
    if not integration:
        return

    try:
        if command_name == 'scan_discovery':
            call_command('scan_discovery', cidr=options.get('cidr', '192.168.1.0/24'), skip_telegram=True)
        elif command_name == 'scan_services':
            call_command('scan_services', targets=options.get('targets', 'from_db'), skip_telegram=True)
        else:
            send_telegram_to_integration(integration, f"Unknown command: {command_name}")
            return

        # Build summary from last task execution (include nmap/output, truncated for Telegram 4096 limit)
        from inventory.models import TaskExecution
        last_run = TaskExecution.objects.filter(task_name=command_name).order_by('-started_at').first()
        if last_run and last_run.completed_at:
            status = "✅" if last_run.status == 'success' else "❌"
            summary = (
                f"{status} <b>Scan finished</b>\n"
                f"Task: {command_name}\n"
                f"Status: {last_run.status}\n"
                f"Items: {last_run.items_processed}\n"
                f"Time: {last_run.completed_at.strftime('%Y-%m-%d %H:%M')}\n\n"
            )
            if last_run.output:
                max_output = 3200
                output_preview = last_run.output if len(last_run.output) <= max_output else last_run.output[:max_output] + "\n... (truncated)"
                summary += "<b>Output:</b>\n<pre>" + escape_telegram_html(output_preview) + "</pre>\n\n"
            summary += "Use /setname &lt;IP&gt; &lt;name&gt; to assign host names."
        else:
            summary = f"✅ <b>{command_name}</b> completed. Use /setname &lt;IP&gt; &lt;name&gt; to assign host names."
        send_telegram_to_integration(integration, summary)
    except Exception as e:
        logger.exception("Telegram scan task failed")
        send_telegram_to_integration(
            integration,
            f"❌ Scan failed: {escape_telegram_html(str(e))}"
        )

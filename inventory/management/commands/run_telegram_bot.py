"""
Run Telegram bot in long-polling mode. No webhook needed; backend pulls updates from Telegram.
Use this when you don't want to expose your domain (no public URL required).
"""
import logging
import time
import requests
from django.core.management.base import BaseCommand

from inventory.models import IntegrationConfig
from inventory.telegram_bot import handle_update

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run Telegram bot in polling mode (getUpdates). No webhook or public URL needed.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--integration-id',
            type=int,
            default=None,
            help='Telegram integration PK to use (default: first enabled)',
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=30,
            help='Long-poll timeout in seconds (default: 30)',
        )

    def handle(self, *args, **options):
        integration_id = options['integration_id']
        timeout = max(10, min(300, options['timeout']))

        if integration_id:
            integration = IntegrationConfig.objects.filter(
                pk=integration_id, name='telegram', enabled=True
            ).first()
        else:
            integration = IntegrationConfig.objects.filter(
                name='telegram', enabled=True
            ).order_by('display_name').first()

        if not integration:
            self.stderr.write(self.style.ERROR(
                'No enabled Telegram integration found. Add one in Settings > Integrations.'
            ))
            return

        token = integration.get_config('bot_token', '').strip()
        if not token:
            self.stderr.write(self.style.ERROR('Bot token not configured for this integration.'))
            return

        # Remove webhook so getUpdates works (Telegram allows only one method per bot)
        try:
            r = requests.get(
                f'https://api.telegram.org/bot{token}/deleteWebhook',
                timeout=10,
            )
            if r.ok and r.json().get('ok'):
                self.stdout.write('Webhook removed (using polling).')
        except requests.RequestException as e:
            logger.warning('deleteWebhook failed: %s', e)

        url = f'https://api.telegram.org/bot{token}/getUpdates'
        offset = None
        self.stdout.write(self.style.SUCCESS(
            f'Polling for updates (integration: {integration.display_name or "Default"}). Ctrl+C to stop.'
        ))

        while True:
            try:
                params = {'timeout': timeout}
                if offset is not None:
                    params['offset'] = offset

                r = requests.get(url, params=params, timeout=timeout + 10)
                data = r.json()
                if not data.get('ok'):
                    self.stderr.write(self.style.WARNING(
                        f'getUpdates error: {data.get("description", "unknown")}'
                    ))
                    time.sleep(5)
                    continue

                for upd in data.get('result', []):
                    offset = upd.get('update_id', 0) + 1
                    try:
                        handle_update(integration, upd)
                    except Exception as e:
                        logger.exception('Error handling update: %s', e)

            except requests.RequestException as e:
                logger.warning('getUpdates request failed: %s', e)
                time.sleep(5)
            except KeyboardInterrupt:
                self.stdout.write('Stopped.')
                break

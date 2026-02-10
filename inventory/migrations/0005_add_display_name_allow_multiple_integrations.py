# Generated manually for multiple integrations per type

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0004_add_hostname_model'),
    ]

    operations = [
        migrations.AddField(
            model_name='integrationconfig',
            name='display_name',
            field=models.CharField(blank=True, default='Default', help_text='Label for this instance (e.g. Main, Alerts)', max_length=100),
        ),
        migrations.AlterField(
            model_name='integrationconfig',
            name='name',
            field=models.CharField(choices=[('telegram', 'Telegram'), ('proxmox', 'Proxmox'), ('docker', 'Docker'), ('adguard', 'AdGuard Home')], help_text='Integration type', max_length=50),
        ),
        migrations.AddConstraint(
            model_name='integrationconfig',
            constraint=models.UniqueConstraint(fields=('name', 'display_name'), name='unique_integration_name_display'),
        ),
    ]

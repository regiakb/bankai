# Generated manually for HostStatusEvent

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('inventory', '0005_add_display_name_allow_multiple_integrations'),
    ]

    operations = [
        migrations.CreateModel(
            name='HostStatusEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('recorded_at', models.DateTimeField(auto_now_add=True)),
                ('is_online', models.BooleanField(help_text='True = came online, False = went offline')),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='status_events', to='inventory.host')),
            ],
            options={
                'ordering': ['-recorded_at'],
                'verbose_name': 'Host status event',
                'verbose_name_plural': 'Host status events',
            },
        ),
        migrations.AddIndex(
            model_name='hoststatusevent',
            index=models.Index(fields=['host', '-recorded_at'], name='inventory_h_host_id_7a8b0d_idx'),
        ),
        migrations.AddIndex(
            model_name='hoststatusevent',
            index=models.Index(fields=['-recorded_at'], name='inventory_h_recorded_9c4e2a_idx'),
        ),
    ]

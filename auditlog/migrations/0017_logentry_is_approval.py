# Generated by Django 5.0.2 on 2024-03-12 06:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("auditlog", "0016_logentry_domain_object_id_logentry_path"),
    ]

    operations = [
        migrations.AddField(
            model_name="logentry",
            name="is_approval",
            field=models.BooleanField(
                blank=True, default=False, null=True, verbose_name="is approval"
            ),
        ),
    ]
